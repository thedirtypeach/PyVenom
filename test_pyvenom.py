import ipaddress
import unittest

import pyvenom

# Shape of python-nmap 0.7.1's PortScanner.scan() return value, trimmed to the keys used.
SAMPLE = {
    "scan": {
        "10.0.0.5": {
            "hostnames": [{"name": "desktop", "type": "PTR"}],
            "status": {"state": "up"},
            "tcp": {
                445: {"state": "open", "name": "microsoft-ds"},
                8080: {"state": "open", "name": "http-proxy"},
                21: {"state": "filtered", "name": "ftp"},
            },
        }
    }
}


class ParseResults(unittest.TestCase):
    def setUp(self):
        self.findings = pyvenom.parse_results(SAMPLE)

    def test_one_finding_per_port_sorted(self):
        self.assertEqual([f["port"] for f in self.findings], [21, 445, 8080])

    def test_fields(self):
        smb = self.findings[1]
        self.assertEqual(smb["host"], "10.0.0.5")
        self.assertEqual(smb["hostname"], "desktop")
        self.assertEqual(smb["protocol"], "tcp")
        self.assertEqual(smb["state"], "open")
        self.assertEqual(smb["service"], "microsoft-ds")

    def test_advice_only_for_open_ports_with_a_source(self):
        by_port = {f["port"]: f for f in self.findings}
        self.assertIn("445", by_port[445]["advice"])
        self.assertIsNotNone(by_port[445]["source"])
        self.assertIsNone(by_port[8080]["advice"])  # open, but no verified source
        self.assertIsNone(by_port[21]["advice"])   # has advice, but filtered, not open

    def test_empty_scan(self):
        self.assertEqual(pyvenom.parse_results({"scan": {}}), [])
        self.assertEqual(pyvenom.parse_results({}), [])


class Advice(unittest.TestCase):
    def test_every_entry_cites_a_url(self):
        for port, (advice, source) in pyvenom.ADVICE.items():
            self.assertTrue(advice, port)
            self.assertIn("https://", source, port)


class LocalIp(unittest.TestCase):
    def test_returns_ipv4(self):
        ipaddress.IPv4Address(pyvenom.get_local_ip())


if __name__ == "__main__":
    unittest.main()
