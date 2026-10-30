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


if __name__ == "__main__":
    unittest.main()
