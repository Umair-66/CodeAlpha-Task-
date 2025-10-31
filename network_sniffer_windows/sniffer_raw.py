#!/usr/bin/env python3
"""
sniffer_raw.py
Raw-socket based sniffer (Linux/macOS). Included for reference/learning.
NOTE: Raw Ethernet sockets are typically NOT available on Windows.
"""

import argparse, socket, struct, sys

ETH_P_ALL = 0x0003

def mac_addr(b):
    return ":".join(f"{x:02x}" for x in b)

def safe_preview(b, limit=64):
    b = b[:limit]
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)

def parse_ipv4_header(data):
    ver_ihl = data[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    ttl, proto, src, dst = struct.unpack("!8xBB2x4s4s", data[:20])
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    return version, ihl, ttl, proto, src_ip, dst_ip

def parse_tcp_header(data):
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack("!HHLLH", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF
    return src_port, dst_port, seq, ack, offset, flags

def parse_udp_header(data):
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
    return src_port, dst_port, length

def main():
    ap = argparse.ArgumentParser(description="Raw Socket Network Sniffer (Linux/macOS)")
    ap.add_argument("-i", "--iface", required=True, help="Interface (e.g., eth0)")
    ap.add_argument("-c", "--count", type=int, default=0, help="Packets to capture (0 = infinite)")
    args = ap.parse_args()

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        print("[-] Need root privileges to open raw socket.")
        sys.exit(1)
    sock.bind((args.iface, 0))

    print(f"[+] Sniffing on {args.iface} (raw sockets) count={args.count or '∞'}")

    captured = 0
    while True:
        packet, addr = sock.recvfrom(65535)
        eth_hdr = packet[:14]
        dst, src, eth_type = struct.unpack("!6s6sH", eth_hdr)
        l2_info = f"ETH {mac_addr(src)} -> {mac_addr(dst)} type=0x{eth_type:04x}"
        offset = 14
        out = [l2_info]

        if eth_type == 0x0800 and len(packet) >= offset + 20:
            try:
                version, ihl, ttl, proto, src_ip, dst_ip = parse_ipv4_header(packet[offset:offset+20])
                out.append(f"IPv4 {src_ip} -> {dst_ip} proto={proto} ttl={ttl}")
                offset += ihl
                if proto == 6 and len(packet) >= offset + 20:
                    sport, dport, seq, ack, doff, flags = parse_tcp_header(packet[offset:offset+20])
                    out.append(f"TCP {sport}->{dport} seq={seq} ack={ack} flags=0x{flags:x}")
                    offset += doff
                    payload = packet[offset:]
                    if payload:
                        out.append("DATA: " + safe_preview(payload))
                elif proto == 17 and len(packet) >= offset + 8:
                    sport, dport, length = parse_udp_header(packet[offset:offset+8])
                    out.append(f"UDP {sport}->{dport} len={length}")
                    offset += 8
                    payload = packet[offset:]
                    if payload:
                        out.append("DATA: " + safe_preview(payload))
            except Exception as e:
                out.append(f"(parse error: {e})")
        print(" | ".join(out))
        captured += 1
        if args.count and captured >= args.count:
            break

if __name__ == "__main__":
    main()
