'''
PyVenom - scan a machine for open ports and flag the risky ones.

By default it scans the machine it runs on, at the address other devices on the
network reach it by, so the result is what the local network can see.
'''

import argparse
import json
import socket
import sys

import nmap

# Ports 1-1024 plus common services that live above them.
DEFAULT_PORTS = "1-1024,3306,3389,5900,8080,8443"

# Advice for risky open ports. Each entry cites the primary source it rests on;
# ports without a verified source are reported without advice.
MS03_026 = ("Microsoft Security Bulletin MS03-026, Technical details (Mitigating factors, Workarounds): "
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-026")
ADVICE = {
    21: ("FTP sends passwords and data unencrypted. Use SFTP/FTPS or disable the FTP server.",
         "RFC 2577, FTP Security Considerations, sections 5-6: https://www.rfc-editor.org/rfc/rfc2577"),
    23: ("Telnet predates SSH and offers far weaker security. Use SSH and disable Telnet.",
         "RFC 4251, SSH Protocol Architecture, section 4.1: https://www.rfc-editor.org/rfc/rfc4251"),
    135: ("MS-RPC endpoint mapper. RPC is not meant for hostile networks like the internet; "
          "block TCP 135 inbound from the internet at the firewall.", MS03_026),
    139: ("NetBIOS session service. Block TCP 139 inbound from the internet at the firewall.", MS03_026),
    445: ("SMB. Block TCP 445 inbound from the internet, and make sure SMBv1 is disabled "
          "(Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
          "Microsoft Learn, Secure SMB Traffic in Windows Server (Block inbound SMB access): "
          "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic ; "
          "Detect, enable, and disable SMBv1, SMBv2, and SMBv3 in Windows: "
          "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"),
    593: ("RPC over HTTP endpoint mapper. Block TCP 593 inbound from the internet at the firewall.", MS03_026),
    3306: ("MySQL should not be reachable from untrusted hosts. Firewall it or bind it to localhost.",
           "MySQL 8.4 Reference Manual, 8.1.1 Security Guidelines: "
           "https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html"),
    3389: ("RDP. Do not expose it directly to the internet; Microsoft calls that a security risk.",
           "Microsoft Learn, Troubleshoot RDP blocked by NSG rules on Azure VMs (Secure RDP access for "
           "production environments): https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/"
           "windows/troubleshoot-rdp-nsg-problem"),
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


def print_report(target, findings):
    print(f"Target: {target}")
    if not findings:
        print("Host is up; no open or filtered ports found.")
        return
    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<14}ADVICE")
    for f in findings:
        print(f"{f['port']:>5}/{f['protocol']:<4}{f['state']:<10}{f['service']:<14}{f['advice'] or ''}")
    sources = sorted({f["source"] for f in findings if f["source"]})
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
        result = nmap.PortScanner().scan(target, args.ports)
    except nmap.PortScannerError as e:
        if "not found" in str(e):
            sys.exit("nmap is not installed or not on PATH: https://nmap.org/download")
        sys.exit(f"nmap failed: {e}")
    if not result.get("scan"):
        # nmap reports a host it cannot resolve or reach as zero hosts up, not as an error.
        # python-nmap repeats nmap's stderr per error, so keep each line once.
        stderr = "\n".join(result.get("nmap", {}).get("scaninfo", {}).get("error", []))
        lines = dict.fromkeys(l.strip() for l in stderr.splitlines() if l.strip())
        sys.exit("\n".join([f"{target} could not be resolved or did not respond.", *lines]))

    findings = parse_results(result)
    if args.json:
        print(json.dumps({"target": target, "findings": findings}, indent=2))
    else:
        print_report(target, findings)


if __name__ == "__main__":
    main()
