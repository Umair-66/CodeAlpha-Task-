#!/usr/bin/env python3
"""
sniffer_scapy.py
Windows-friendly basic network sniffer using Scapy.

Requirements:
 - Python 3.8+
 - scapy
 - Npcap installed (WinPcap-compatible mode)
Run as Administrator.

Example:
  python sniffer_scapy.py -i "Ethernet" -f "udp and port 53" -c 20
"""

import argparse
import sys
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, Raw, conf, get_if_list

def safe_preview(payload_bytes, limit=128):
    if payload_bytes is None:
        return ""
    s = payload_bytes[:limit]
    try:
        text = s.decode("utf-8", errors="replace")
    except Exception:
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in s)
    return text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

def handle_packet(pkt):
    parts = []
    # L2
    try:
        if Ether in pkt:
            eth = pkt[Ether]
            parts.append(f"ETH {eth.src} -> {eth.dst} type=0x{eth.type:04x}")
    except Exception:
        pass

    # L3
    try:
        if IP in pkt:
            ip = pkt[IP]
            parts.append(f"IPv4 {ip.src} -> {ip.dst} proto={ip.proto} ttl={ip.ttl}")
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            parts.append(f"IPv6 {ip6.src} -> {ip6.dst} nh={ip6.nh} hlim={ip6.hlim}")
    except Exception:
        pass

    # L4
    try:
        if TCP in pkt:
            tcp = pkt[TCP]
            parts.append(f"TCP {tcp.sport} -> {tcp.dport} flags={tcp.flags}")
        elif UDP in pkt:
            udp = pkt[UDP]
            parts.append(f"UDP {udp.sport} -> {udp.dport} len={udp.len}")
    except Exception:
        pass

    # Payload preview
    try:
        if Raw in pkt:
            payload = pkt[Raw].load
            parts.append("DATA: " + safe_preview(payload, limit=128))
    except Exception:
        pass

    print(" | ".join(parts))

def list_interfaces():
    # Scapy's get_if_list lists interfaces; display them to user
    ifs = get_if_list()
    for i, name in enumerate(ifs):
        print(f"{i+1:2d}. {name}")
    print("\nTip: Use the exact interface name shown above with -i")

def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (Scapy) - Windows")
    parser.add_argument("-i", "--iface", required=False, help="Interface name (exact). Use --list to show available interfaces.")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (e.g., 'tcp or udp', 'udp and port 53')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--list", action="store_true", help="List interfaces and exit")
    args = parser.parse_args()

    if args.list or not args.iface:
        print("[*] Available interfaces:")
        list_interfaces()
        if not args.iface:
            print("\nUse -i with an interface name to start sniffing (run as Administrator).")
            return

    print(f"[+] Sniffing on interface: {args.iface}  filter=({args.filter or 'none'})  count={args.count or '∞'}")
    try:
        # On Windows, Scapy's sniff will use npcap (if installed). Run as admin.
        sniff(iface=args.iface, filter=(args.filter or None), prn=handle_packet, store=False, count=args.count or 0)
    except PermissionError:
        print("[-] PermissionError: run your terminal as Administrator and ensure Npcap is installed.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
