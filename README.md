# PyVenom

Scan a machine for open ports and flag the risky ones, with remediation advice that cites its source.

By default PyVenom scans the computer it runs on, at its LAN address, so you see what other devices on your network can reach.

Only scan machines you own or have permission to test.

## Requirements

- Python 3.9+
- [Nmap](https://nmap.org/download) on `PATH`. On Windows use the installer (it includes Npcap and adds Nmap to `PATH`).

## Install

```powershell
git clone https://github.com/thedirtypeach/PyVenom.git
cd PyVenom
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```powershell
python pyvenom.py                       # this machine, default ports
python pyvenom.py 192.168.1.10          # another host
python pyvenom.py -p 22,80,443,3389     # custom ports (any nmap port list, e.g. 1-65535)
python pyvenom.py --json                # machine-readable output
```

Default ports: `1-1024,3306,3389,5900,8080,8443`.

Example:

```
Scanning 192.168.1.20 (ports 1-1024,3306,3389,5900,8080,8443)...
Target: 192.168.1.20
PORT      STATE     SERVICE       ADVICE
  135/tcp open      msrpc
  139/tcp open      netbios-ssn
  445/tcp open      microsoft-ds  SMB. Block TCP 445 inbound from the internet, and make sure SMBv1 is disabled (...)

Sources:
  - Microsoft Learn, Secure SMB Traffic in Windows Server (Block inbound SMB access): https://learn.microsoft.com/...
```

`--json` prints `{"target": ..., "findings": [...]}`; each finding has `host`, `hostname`, `protocol`, `port`, `state`, `service`, `advice`, `source`.

Exit code is 1 when nmap is missing or the target cannot be resolved or reached.

## Advice

Advice is shown only for open ports, and only where a primary source backs it:

| Port | Advice | Source |
|---|---|---|
| 21 FTP | Sends passwords unencrypted; use SFTP/FTPS | [RFC 2577](https://www.rfc-editor.org/rfc/rfc2577) sections 5-6 |
| 23 Telnet | Far weaker than SSH; use SSH | [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251) section 4.1 |
| 135 MS-RPC, 139 NetBIOS, 593 RPC over HTTP | Block inbound from the internet | [MS03-026](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-026) Technical details |
| 445 SMB | Block inbound from the internet; disable SMBv1 | [Secure SMB Traffic](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic), [SMBv1](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3) |
| 3306 MySQL | Not reachable from untrusted hosts | [MySQL 8.4 Security Guidelines](https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html) |
| 3389 RDP | Do not expose directly to the internet | [Troubleshoot RDP blocked by NSG rules](https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/troubleshoot-rdp-nsg-problem), "Secure RDP access for production environments" |
| 5900 VNC | Built-in auth is weak; tunnel over SSH/VPN | [RFC 6143](https://www.rfc-editor.org/rfc/rfc6143) section 7.2.2 |

Other open ports are listed without advice until a primary source is added. To add one, put an entry in `ADVICE` in `pyvenom.py` with the source's title, section, and URL.

## Tests

```powershell
python -m unittest
```

Tests cover result parsing and the advice table; they do not need nmap or a network.

## Roadmap

- Inventory installed software and versions on Windows and compare against known-vulnerable versions.
