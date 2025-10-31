# Basic Network Sniffer (Windows) - Project

This repository contains a simple network sniffer implemented in Python using **Scapy** (Windows-friendly) and a raw-socket reference implementation for Linux/macOS.

> ⚠️ **Important:** Only run this on networks you own or have explicit permission to test. Sniffing network traffic can capture sensitive information.

## Files
- `sniffer_scapy.py` — Primary Windows-friendly sniffer using **Scapy**. Run as Administrator.  
- `sniffer_raw.py` — Educational raw-socket sniffer for Linux/macOS (provided for learning; not for Windows).  
- `requirements.txt` — Python dependencies.  
- `RUN_WINDOWS_STEPS.txt` — Step-by-step instructions to set up and run on Windows 10.  
- `LICENSE` — MIT License.

## Quick start (Windows)
1. Install Python 3.8+ and add to PATH.
2. Install [Npcap](https://nmap.org/npcap/) — choose "WinPcap API-compatible mode".
3. Open an elevated (Administrator) PowerShell or CMD.
4. Create and activate a virtual environment (optional but recommended).
5. Install Python dependencies: `pip install -r requirements.txt`
6. List interfaces: `python sniffer_scapy.py --list`
7. Run sniffing (example): `python sniffer_scapy.py -i "Ethernet" -f "udp and port 53" -c 20`

See `RUN_WINDOWS_STEPS.txt` for full step-by-step guidance.

## Ethical & Legal
- Only capture traffic on networks you own or have explicit permission to test.
- Avoid saving or sharing payloads that may contain personal or sensitive data.

## License
MIT
