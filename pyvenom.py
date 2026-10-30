'''
PyVenom - scan a machine for open ports and flag the risky ones.

By default it scans the machine it runs on, at the address other devices on the
network reach it by, so the result is what the local network can see.
'''

import argparse
import json
import re
import socket
import sys

import nmap

# python-nmap shlex-splits the target into nmap's argv, so a target like "-iL file" or
# "x --script y" would become nmap options. Allow only one host, IP, or CIDR range.
TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:/-]{0,252}")
PORTS_RE = re.compile(r"[0-9][0-9,-]{0,199}")


class ScanError(Exception):
    pass

# Ports 1-1024 plus common services that live above them.
DEFAULT_PORTS = "1-1024,3306,3389,5900,8080,8443"

# Advice for risky open ports. Each entry cites the primary source it rests on;
# ports without a verified source are reported without advice.
ADVICE = {
    21: ("FTP sends passwords and data unencrypted. Use SFTP/FTPS or disable the FTP server.",
         "RFC 2577, FTP Security Considerations, sections 5-6: https://www.rfc-editor.org/rfc/rfc2577"),
    23: ("Telnet predates SSH and offers far weaker security. Use SSH and disable Telnet.",
         "RFC 4251, SSH Protocol Architecture, section 4.1: https://www.rfc-editor.org/rfc/rfc4251"),
    445: ("SMB. Block TCP 445 inbound from the internet, and make sure SMBv1 is disabled "
          "(Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
          "Microsoft Learn, Secure SMB Traffic in Windows Server (Block inbound SMB access): "
          "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic ; "
          "Detect, enable, and disable SMBv1, SMBv2, and SMBv3 in Windows: "
          "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"),
    3306: ("MySQL should not be reachable from untrusted hosts. Firewall it or bind it to localhost.",
           "MySQL 8.4 Reference Manual, 8.1.1 Security Guidelines: "
           "https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html"),
    5900: ("VNC's built-in authentication is cryptographically weak. Tunnel VNC over SSH or a VPN.",
           "RFC 6143, Remote Framebuffer Protocol, section 7.2.2: https://www.rfc-editor.org/rfc/rfc6143"),
}


def get_local_ip():
    '''Return the IPv4 address of the interface that carries the default route.

    socket.gethostbyname(socket.gethostname()) is unreliable for this: on Debian-based
    systems the hostname maps to 127.0.1.1 (Debian Reference, 5.1.1), and on machines with
    several adapters it can return a VPN or virtual adapter. Connecting a UDP socket sends
    no packets; it only makes the OS pick the outbound interface.
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1 (RFC 5737): never routed on the internet
            return s.getsockname()[0]
        except OSError:  # no network route at all
            return "127.0.0.1"


def parse_results(scan_result):
    '''Flatten python-nmap's scan() result into one dict per port.'''
    findings = []
    for host, data in scan_result.get("scan", {}).items():
        hostnames = [h["name"] for h in data.get("hostnames", []) if h.get("name")]
        for proto in ("tcp", "udp"):
            for port, info in sorted(data.get(proto, {}).items()):
                advice, source = ADVICE.get(port, (None, None)) if info["state"] == "open" else (None, None)
                findings.append({
                    "host": host,
                    "hostname": hostnames[0] if hostnames else "",
                    "protocol": proto,
                    "port": port,
                    "state": info["state"],
                    "service": info.get("name", ""),
                    "advice": advice,
                    "source": source,
                })
    return findings


def run_scan(target, ports=DEFAULT_PORTS):
    '''Scan target and return findings. Raises ScanError with a user-facing message.'''
    if not TARGET_RE.fullmatch(target):
        raise ScanError(f"Invalid target {target!r}: use one hostname, IP address, or CIDR range.")
    if not PORTS_RE.fullmatch(ports):
        raise ScanError(f"Invalid ports {ports!r}: use numbers, commas, and ranges, e.g. 22,80,8000-8100.")
    try:
        result = nmap.PortScanner().scan(target, ports)
    except nmap.PortScannerError as e:
        if "not found" in str(e):
            raise ScanError("nmap is not installed or not on PATH: https://nmap.org/download") from e
        raise ScanError(f"nmap failed: {e}") from e
    if not result.get("scan"):
        # nmap reports a host it cannot resolve or reach as zero hosts up, not as an error.
        # python-nmap repeats nmap's stderr per error, so keep each line once.
        stderr = "\n".join(result.get("nmap", {}).get("scaninfo", {}).get("error", []))
        lines = dict.fromkeys(l.strip() for l in stderr.splitlines() if l.strip())
        raise ScanError("\n".join([f"{target} could not be resolved or did not respond.", *lines]))
    return parse_results(result)


def cited_sources(findings):
    return sorted({f["source"] for f in findings if f["source"]})


def print_report(target, findings):
    print(f"Target: {target}")
    if not findings:
        print("Host is up; no open or filtered ports found.")
        return
    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<14}ADVICE")
    for f in findings:
        print(f"{f['port']:>5}/{f['protocol']:<4}{f['state']:<10}{f['service']:<14}{f['advice'] or ''}")
    sources = cited_sources(findings)
    if sources:
        print("\nSources:")
        for s in sources:
            print(f"  - {s}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan a host for open ports and flag risky ones.")
    parser.add_argument("target", nargs="?", help="IP or hostname to scan (default: this machine's LAN address)")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help=f"nmap port list (default: {DEFAULT_PORTS})")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    args = parser.parse_args(argv)

    target = args.target or get_local_ip()
    if not args.json:
        print(f"Scanning {target} (ports {args.ports})...")
    try:
        findings = run_scan(target, args.ports)
    except ScanError as e:
        sys.exit(str(e))

    if args.json:
        print(json.dumps({"target": target, "findings": findings}, indent=2))
    else:
        print_report(target, findings)


if __name__ == "__main__":
    main()
