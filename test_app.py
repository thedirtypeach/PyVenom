import unittest
from unittest import mock

import app as webapp
import pyvenom

FINDINGS = [
    {"host": "10.0.0.5", "hostname": "", "protocol": "tcp", "port": 135, "state": "open",
     "service": "msrpc", "advice": None, "source": None},
    {"host": "10.0.0.5", "hostname": "", "protocol": "tcp", "port": 445, "state": "open",
     "service": "microsoft-ds", "advice": pyvenom.ADVICE[445][0], "source": pyvenom.ADVICE[445][1]},
]


class WebApp(unittest.TestCase):
    def setUp(self):
        self.client = webapp.app.test_client()

    def post(self, **form):
        return self.client.post("/scan", data={"token": webapp.TOKEN, **form})

    def test_index_has_form_and_token(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(webapp.TOKEN.encode(), r.data)

    def test_scan_without_token_is_refused(self):
        with mock.patch.object(pyvenom, "run_scan") as run:
            r = self.client.post("/scan", data={"target": "10.0.0.5"})
        self.assertEqual(r.status_code, 403)
        run.assert_not_called()

    def test_foreign_host_header_is_refused(self):
        r = self.client.get("/", headers={"Host": "evil.example:5000"})
        self.assertEqual(r.status_code, 403)

    def test_scan_renders_findings_and_linked_sources(self):
        with mock.patch.object(pyvenom, "run_scan", return_value=FINDINGS) as run:
            r = self.post(target="10.0.0.5", ports="135,445")
        run.assert_called_once_with("10.0.0.5", "135,445")
        html = r.data.decode()
        self.assertIn("microsoft-ds", html)
        self.assertIn('class="risky"', html)
        self.assertIn('<a href="https://learn.microsoft.com/', html)

    def test_scan_error_is_shown(self):
        with mock.patch.object(pyvenom, "run_scan", side_effect=pyvenom.ScanError("nmap is not installed")):
            r = self.post(target="10.0.0.5")
        self.assertIn(b"nmap is not installed", r.data)

    def test_option_injection_never_reaches_nmap(self):
        with mock.patch("nmap.PortScanner") as scanner:
            r = self.post(target="-iL C:\\secret.txt", ports="80")
        scanner.assert_not_called()
        self.assertIn(b"Invalid target", r.data)

    def test_output_is_escaped(self):
        with mock.patch.object(pyvenom, "run_scan", side_effect=pyvenom.ScanError("<script>x</script>")):
            r = self.post(target="10.0.0.5")
        self.assertNotIn(b"<script>x</script>", r.data)


AUDIT = {
    "updates": [{"name": "Wireshark", "id": "WiresharkFoundation.Wireshark", "installed": "4.6.4", "available": "4.6.9"}],
    "cve_checks": [
        {"name": "Wireshark", "id": "WiresharkFoundation.Wireshark", "installed": "4.6.4",
         "cpe": "cpe:2.3:a:wireshark:wireshark:4.6.4", "update_available": "4.6.9",
         "cves": [{"id": f"CVE-2026-{n:04d}", "severity": "HIGH", "score": 8.1, "cvss": "3.1",
                   "known_exploited": n == 1, "url": f"https://nvd.nist.gov/vuln/detail/CVE-2026-{n:04d}"}
                  for n in range(1, 8)]},
        {"name": "Git", "id": "Git.Git", "installed": "2.55.0.5", "cpe": "cpe:2.3:a:git-scm:git:2.55.0",
         "update_available": "2.56.0.4", "cves": []},
    ],
}


class SoftwarePage(unittest.TestCase):
    def setUp(self):
        self.client = webapp.app.test_client()

    def test_form(self):
        r = self.client.get("/software")
        self.assertEqual(r.status_code, 200)
        self.assertIn(webapp.TOKEN.encode(), r.data)
        self.assertIn(b'class="active">Software', r.data)

    def test_audit_without_token_is_refused(self):
        with mock.patch.object(webapp.software, "get_packages") as get:
            r = self.client.post("/software", data={"cves": "1"})
        self.assertEqual(r.status_code, 403)
        get.assert_not_called()

    def test_audit_renders_cves_kev_and_updates(self):
        with mock.patch.object(webapp.software, "get_packages", return_value=[]), \
             mock.patch.object(webapp.software, "audit", return_value=AUDIT) as audit:
            r = self.client.post("/software", data={"token": webapp.TOKEN, "cves": "1"})
        audit.assert_called_once_with([], check_cves=True, api_key=mock.ANY)
        html = r.data.decode()
        self.assertIn("1 KNOWN EXPLOITED", html)
        self.assertIn('<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001">', html)
        self.assertIn("2 more", html)            # 7 CVEs, top 5 shown
        self.assertIn("Update to 4.6.9", html)
        self.assertIn("Updates available (1)", html)

    def test_unchecked_box_skips_cves(self):
        with mock.patch.object(webapp.software, "get_packages", return_value=[]), \
             mock.patch.object(webapp.software, "audit", return_value={"updates": [], "cve_checks": []}) as audit:
            r = self.client.post("/software", data={"token": webapp.TOKEN})
        self.assertFalse(audit.call_args.kwargs["check_cves"])
        self.assertIn(b"Everything winget manages is up to date.", r.data)

    def test_audit_error_is_shown(self):
        with mock.patch.object(webapp.software, "get_packages",
                               side_effect=webapp.software.AuditError("Needs the WinGet PowerShell module.")):
            r = self.client.post("/software", data={"token": webapp.TOKEN, "cves": "1"})
        self.assertIn(b"Needs the WinGet PowerShell module.", r.data)


if __name__ == "__main__":
    unittest.main()
