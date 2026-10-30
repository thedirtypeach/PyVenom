'''
PyVenom software audit (Windows).

1. Lists installed software that winget can update.
2. For a curated set of common apps, looks up CVEs that the NVD records against the
   installed version.

Matching Windows software to NVD products is only reliable for known apps, so CVE lookups
are limited to CURATED; every other app is covered by the update check alone.
'''

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

# (winget Id pattern, NVD CPE vendor:product, version components the NVD uses).
# winget versions often carry extra components (Git 2.56.0.4, WinRAR 7.23.0, PuTTY 0.85.0.0)
# that NVD CPE names do not; checked against both catalogs on 2026-10-30.
CURATED = [
    (r"Mozilla\.Firefox", "mozilla:firefox", 3),
    (r"Google\.Chrome", "google:chrome", 4),
    (r"7zip\.7zip", "7-zip:7-zip", 2),
    (r"VideoLAN\.VLC", "videolan:vlc_media_player", 3),
    (r"Notepad\+\+\.Notepad\+\+", r"notepad-plus-plus:notepad\+\+", 4),
    (r"WiresharkFoundation\.Wireshark", "wireshark:wireshark", 3),
    (r"RARLab\.WinRAR", "rarlab:winrar", 2),
    (r"Git\.Git", "git-scm:git", 3),
    (r"Python\.Python\.3\.\d+", "python:python", 3),
    (r"OpenJS\.NodeJS(\.LTS)?", "nodejs:node.js", 3),
    (r"PuTTY\.PuTTY", "putty:putty", 2),
    (r"Microsoft\.VisualStudioCode", "microsoft:visual_studio_code", 3),
    (r"WinSCP\.WinSCP", "winscp:winscp", 3),
    (r"DominikReichl\.KeePass", "keepass:keepass", 3),
]

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD allows 5 requests per rolling 30 s without an API key, 50 with one
# (nvd.nist.gov/developers/start-here, "Rate Limits").
NVD_DELAY = {False: 6.5, True: 0.7}

# winget's PowerShell module returns real objects; `winget list` text truncates names and Ids
# to the console width.
PS_LIST = (
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    "Import-Module Microsoft.WinGet.Client -ErrorAction Stop; "
    "Get-WinGetPackage | Select-Object Name, Id, InstalledVersion, IsUpdateAvailable, Source, "
    "@{n='AvailableVersion'; e={ $_.AvailableVersions | Select-Object -First 1 }} | ConvertTo-Json -Compress"
)


class AuditError(Exception):
    pass


def get_packages():
    '''Installed packages as dicts: Name, Id, InstalledVersion, IsUpdateAvailable, Source, AvailableVersion.'''
    if sys.platform != "win32":
        raise AuditError("The software audit needs Windows and winget.")
    # Windows' default execution policy (Restricted) refuses the module's signed format file
    # ("AuthorizationManager check failed"). RemoteSigned, for this process only, accepts
    # Microsoft-signed files without allowing unsigned downloaded scripts.
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned",
                        "-Command", PS_LIST], capture_output=True, text=True, encoding="utf-8")
    if p.returncode != 0:
        if "Modules_ModuleNotFound" in p.stderr:
            raise AuditError("Needs the WinGet PowerShell module. Install it with:\n"
                             "  Install-Module Microsoft.WinGet.Client -Scope CurrentUser")
        raise AuditError(f"Listing packages failed:\n{p.stderr.strip()}")
    return parse_packages(p.stdout)


def parse_packages(text):
    data = json.loads(text) if text.strip() else []
    return [data] if isinstance(data, dict) else data  # ConvertTo-Json unwraps a single item


def curated_match(package):
    '''Return (cpe_vendor_product, nvd_version) for a curated package, else None.'''
    version = package.get("InstalledVersion") or ""
    if not re.fullmatch(r"\d+(\.\d+)*", version):  # "Unknown", "< 1.2", etc.
        return None
    for pattern, cpe, parts in CURATED:
        if re.fullmatch(pattern, package.get("Id") or ""):
            return cpe, ".".join(version.split(".")[:parts])
    return None


def parse_cves(nvd_response):
    '''Flatten an NVD CVE API 2.0 response into one dict per CVE, highest score first.'''
    cves = []
    for item in nvd_response.get("vulnerabilities", []):
        cve = item["cve"]
        metrics = cve.get("metrics", {})
        severity, score, cvss = None, None, None
        for key, label in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0")):
            if metrics.get(key):
                data = metrics[key][0]["cvssData"]
                severity, score, cvss = data.get("baseSeverity"), data.get("baseScore"), label
                break
        cves.append({
            "id": cve["id"],
            "severity": severity,
            "score": score,
            "cvss": cvss,
            "known_exploited": "cisaExploitAdd" in cve,  # listed in CISA's KEV catalog
            "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        })
    return sorted(cves, key=lambda c: (c["known_exploited"], c["score"] or 0), reverse=True)


def lookup_cves(cpe, version, api_key=None):
    # cpeName + isVulnerable: CVEs whose match criteria (including version ranges) cover this
    # exact version (nvd.nist.gov/developers/vulnerabilities, "cpeName", "isVulnerable").
    name = f"cpe:2.3:a:{cpe}:{version}:*:*:*:*:*:*:*"
    url = f"{NVD_URL}?cpeName={urllib.parse.quote(name, safe=':')}&isVulnerable&noRejected"
    req = urllib.request.Request(url, headers={"apiKey": api_key} if api_key else {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return parse_cves(json.load(r))
    except OSError as e:
        raise AuditError(f"NVD lookup failed for {name}: {e}") from e


def audit(packages, check_cves=True, api_key=None, progress=None):
    updates = [{"name": p["Name"], "id": p["Id"], "installed": p["InstalledVersion"],
                "available": p.get("AvailableVersion")}
               for p in packages if p.get("IsUpdateAvailable")]
    vulnerable = []
    if check_cves:
        targets = [(p, m) for p in packages if (m := curated_match(p))]
        for i, (p, (cpe, version)) in enumerate(targets):
            if i:
                time.sleep(NVD_DELAY[bool(api_key)])
            if progress:
                progress(f"[{i + 1}/{len(targets)}] {p['Name']} {version}")
            vulnerable.append({"name": p["Name"], "id": p["Id"], "installed": p["InstalledVersion"],
                               "cpe": f"cpe:2.3:a:{cpe}:{version}",
                               "update_available": p.get("AvailableVersion") if p.get("IsUpdateAvailable") else None,
                               "cves": lookup_cves(cpe, version, api_key)})
    return {"updates": sorted(updates, key=lambda u: u["name"].lower()), "cve_checks": vulnerable}


def print_report(result, top=5):
    updates = result["updates"]
    print(f"\nUpdates available (winget): {len(updates)}")
    for u in updates:
        print(f"  {u['name'][:44]:<45}{u['installed']:<18} -> {u['available']}")
    if updates:
        print("  Update all with: winget upgrade --all")

    checks = result["cve_checks"]
    if not checks:
        return
    print(f"\nKnown CVEs for installed versions (NVD, {len(checks)} curated apps checked):")
    for c in checks:
        cves = c["cves"]
        kev = sum(x["known_exploited"] for x in cves)
        status = f"{len(cves)} CVEs" + (f", {kev} known exploited" if kev else "") if cves else "none"
        fix = f"  -> update to {c['update_available']}" if cves and c["update_available"] else ""
        print(f"  {c['name'][:44]:<45}{c['installed']:<18} {status}{fix}")
        for x in cves[:top]:
            tag = " KNOWN EXPLOITED" if x["known_exploited"] else ""
            print(f"      {x['id']:<16} {x['severity'] or '?':<8} {x['score'] or '':<5}{tag}  {x['url']}")
        if len(cves) > top:
            print(f"      ... {len(cves) - top} more (use --json for all)")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit installed Windows software: pending updates and known CVEs.")
    parser.add_argument("--no-cve", action="store_true", help="skip NVD lookups (update check only)")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    args = parser.parse_args(argv)
    api_key = os.environ.get("NVD_API_KEY")
    try:
        packages = get_packages()
        if not args.json and not args.no_cve:
            print("Checking NVD" + ("" if api_key else " (no NVD_API_KEY set: ~7 s per app)") + "...")
        result = audit(packages, check_cves=not args.no_cve, api_key=api_key,
                       progress=None if args.json else lambda m: print(f"  {m}", flush=True))
    except AuditError as e:
        sys.exit(str(e))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
