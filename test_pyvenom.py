import ipaddress
import unittest
from unittest import mock

import pyvenom

# Shape of python-nmap 0.7.1's PortScanner.scan() return value, trimmed to the keys used.
SAMPLE = {
    "scan": {
        "10.0.0.5": {
            "hostnames": [{"name": "desktop", "type": "PTR"}],
            "status": {"state": "up"},
            "tcp": {
                445: {"state": "open", "name": "microsoft-ds"},
                135: {"state": "open", "name": "msrpc"},
                21: {"state": "filtered", "name": "ftp"},
            },
        }
    }
}


class ParseResults(unittest.TestCase):
    def setUp(self):
        self.findings = pyvenom.parse_results(SAMPLE)

    def test_one_finding_per_port_sorted(self):
        self.assertEqual([f["port"] for f in self.findings], [21, 135, 445])

    def test_fields(self):
        smb = self.findings[2]
        self.assertEqual(smb["host"], "10.0.0.5")
        self.assertEqual(smb["hostname"], "desktop")
        self.assertEqual(smb["protocol"], "tcp")
        self.assertEqual(smb["state"], "open")
        self.assertEqual(smb["service"], "microsoft-ds")

    def test_advice_only_for_open_ports_with_a_source(self):
        by_port = {f["port"]: f for f in self.findings}
        self.assertIn("445", by_port[445]["advice"])
        self.assertIsNotNone(by_port[445]["source"])
        self.assertIsNone(by_port[135]["advice"])  # open, but no verified source
        self.assertIsNone(by_port[21]["advice"])   # has advice, but filtered, not open

    def test_empty_scan(self):
        self.assertEqual(pyvenom.parse_results({"scan": {}}), [])
        self.assertEqual(pyvenom.parse_results({}), [])


class Advice(unittest.TestCase):
    def test_every_entry_cites_a_url(self):
        for port, (advice, source) in pyvenom.ADVICE.items():
            self.assertTrue(advice, port)
            self.assertIn("https://", source, port)


class Validation(unittest.TestCase):
    def test_rejects_anything_nmap_would_read_as_options(self):
        for target in ("-iL hosts.txt", "10.0.0.1 --script vuln", "-oN out.txt", "a;b", ""):
            with self.subTest(target=target), mock.patch("nmap.PortScanner") as scanner:
                with self.assertRaisesRegex(pyvenom.ScanError, "Invalid target"):
                    pyvenom.run_scan(target, "80")
                scanner.assert_not_called()

    def test_rejects_bad_ports(self):
        for ports in ("-sV", "80 --script x", "abc", ""):
            with self.subTest(ports=ports), self.assertRaisesRegex(pyvenom.ScanError, "Invalid ports"):
                pyvenom.run_scan("10.0.0.1", ports)

    def test_accepts_normal_targets_and_ports(self):
        for target in ("10.0.0.1", "192.168.1.0/24", "scanme.nmap.org", "fe80::1", "host-01"):
            self.assertTrue(pyvenom.TARGET_RE.fullmatch(target), target)
        for ports in ("80", "22,80,443", "1-1024,3389", pyvenom.DEFAULT_PORTS):
            self.assertTrue(pyvenom.PORTS_RE.fullmatch(ports), ports)


class LocalIp(unittest.TestCase):
    def test_returns_ipv4(self):
        ipaddress.IPv4Address(pyvenom.get_local_ip())


if __name__ == "__main__":
    unittest.main()
