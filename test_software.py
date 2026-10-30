import json
import unittest
from unittest import mock

import software


def pkg(name, id, installed, available=None):
    return {"Name": name, "Id": id, "InstalledVersion": installed, "Source": "winget",
            "IsUpdateAvailable": available is not None and available != installed,
            "AvailableVersion": available}


# Trimmed NVD CVE API 2.0 response: one CVSS 3.1 CVE, one CVSS 4.0-only CVE, one KEV-listed CVE.
NVD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2026-0001", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}},
    {"cve": {"id": "CVE-2026-0002", "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 5.5, "baseSeverity": "MEDIUM"}}]}}},
    {"cve": {"id": "CVE-2023-38831", "cisaExploitAdd": "2023-08-24",
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}}]}}},
]}


class ParsePackages(unittest.TestCase):
    def test_list_single_and_empty(self):
        self.assertEqual(len(software.parse_packages(json.dumps([pkg("A", "a", "1"), pkg("B", "b", "2")]))), 2)
        self.assertEqual(software.parse_packages(json.dumps(pkg("A", "a", "1")))[0]["Id"], "a")
        self.assertEqual(software.parse_packages(""), [])


class CuratedMatch(unittest.TestCase):
    def test_version_trimmed_to_nvd_format(self):
        cases = {
            ("Git.Git", "2.55.0.5"): ("git-scm:git", "2.55.0"),
            ("RARLab.WinRAR", "7.23.0"): ("rarlab:winrar", "7.23"),
            ("PuTTY.PuTTY", "0.85.0.0"): ("putty:putty", "0.85"),
            ("Python.Python.3.12", "3.12.10"): ("python:python", "3.12.10"),
            ("OpenJS.NodeJS.LTS", "26.13.0"): ("nodejs:node.js", "26.13.0"),
            ("Notepad++.Notepad++", "8.9.8.1"): (r"notepad-plus-plus:notepad\+\+", "8.9.8.1"),
        }
        for (id, version), expected in cases.items():
            self.assertEqual(software.curated_match(pkg(id, id, version)), expected, id)

    def test_skips_unknown_versions_and_uncurated_apps(self):
        self.assertIsNone(software.curated_match(pkg("Git", "Git.Git", "Unknown")))
        self.assertIsNone(software.curated_match(pkg("Ubisoft", "Ubisoft.Connect", "< 175.0")))
        self.assertIsNone(software.curated_match(pkg("Steam", "Valve.Steam", "2.10.91.91")))
        self.assertIsNone(software.curated_match(pkg("Py", "Python.Launcher", "3.12.10")))


class ParseCves(unittest.TestCase):
    def test_severity_kev_and_order(self):
        cves = software.parse_cves(NVD)
        self.assertEqual([c["id"] for c in cves], ["CVE-2023-38831", "CVE-2026-0001", "CVE-2026-0002"])
        self.assertTrue(cves[0]["known_exploited"])
        self.assertEqual((cves[1]["severity"], cves[1]["score"], cves[1]["cvss"]), ("CRITICAL", 9.8, "3.1"))
        self.assertEqual(cves[2]["cvss"], "4.0")
        self.assertEqual(cves[1]["url"], "https://nvd.nist.gov/vuln/detail/CVE-2026-0001")

    def test_no_metrics(self):
        cve = software.parse_cves({"vulnerabilities": [{"cve": {"id": "CVE-1"}}]})[0]
        self.assertIsNone(cve["severity"])


class Audit(unittest.TestCase):
    PACKAGES = [
        pkg("Wireshark", "WiresharkFoundation.Wireshark", "4.6.4", "4.6.9"),
        pkg("Steam", "Valve.Steam", "2.10.91.91", "2.10.91.91"),
        pkg("Teams", "Microsoft.Teams", "25306.804", "26225.1806"),
    ]

    def test_updates_and_curated_cve_checks(self):
        with mock.patch.object(software, "lookup_cves", return_value=software.parse_cves(NVD)) as lookup, \
             mock.patch.object(software.time, "sleep"):
            result = software.audit(self.PACKAGES)
        self.assertEqual([u["name"] for u in result["updates"]], ["Teams", "Wireshark"])
        lookup.assert_called_once_with("wireshark:wireshark", "4.6.4", None)
        check = result["cve_checks"][0]
        self.assertEqual(check["cpe"], "cpe:2.3:a:wireshark:wireshark:4.6.4")
        self.assertEqual(check["update_available"], "4.6.9")
        self.assertEqual(len(check["cves"]), 3)

    def test_no_cve_skips_nvd(self):
        with mock.patch.object(software, "lookup_cves") as lookup:
            result = software.audit(self.PACKAGES, check_cves=False)
        lookup.assert_not_called()
        self.assertEqual(result["cve_checks"], [])

    def test_waits_between_nvd_requests(self):
        packages = [pkg("Git", "Git.Git", "2.55.0.5"), pkg("WinRAR", "RARLab.WinRAR", "7.23.0")]
        with mock.patch.object(software, "lookup_cves", return_value=[]), \
             mock.patch.object(software.time, "sleep") as sleep:
            software.audit(packages)
        sleep.assert_called_once_with(software.NVD_DELAY[False])


class Lookup(unittest.TestCase):
    def test_request_url_and_api_key_header(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        with mock.patch.object(software.urllib.request, "urlopen", return_value=response) as urlopen, \
             mock.patch.object(software.json, "load", return_value=NVD):
            software.lookup_cves("rarlab:winrar", "6.22", api_key="k")
        req = urlopen.call_args[0][0]
        self.assertIn("cpeName=cpe:2.3:a:rarlab:winrar:6.22:*:*:*:*:*:*:*", software.urllib.parse.unquote(req.full_url))
        self.assertTrue(req.full_url.endswith("&isVulnerable&noRejected"))
        self.assertEqual(req.get_header("Apikey"), "k")


if __name__ == "__main__":
    unittest.main()
