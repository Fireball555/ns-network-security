# VirtualBox setup (host-only isolated network)

Goal: put **ApexGP** (server), **Kali** (attacker) and your **host** (victim) on
the same isolated host-only network `vboxnet0`, with no internet crossover for
the attack traffic.

## 1. Host-only network

VirtualBox → **File → Host Network Manager** → ensure `vboxnet0` exists
(enable its DHCP server, or assign static IPs manually). Your host's `vboxnet0`
interface is usually `192.168.56.1`.

## 2. Kali (attacker) — already correct

From your current config: **Adapter 1 = Host-only (vboxnet0)**, **Adapter 2 =
NAT**. Keep both — NAT gives Kali internet for `apt`/`pip`, host-only puts it on
the lab network. No change needed.

## 3. ApexGP (server) — reconfigure

ApexGP is currently set up for the earlier Ethical Hacking project. You have an
**OVA backup**, so this is safe to revert later.

1. Select **ApexGP → Settings → Network**.
2. **Adapter 1** → *Attached to:* **Host-only Adapter**, *Name:* **vboxnet0**.
3. (Optional) **Adapter 2** → **NAT**, if ApexGP needs internet to install deps.
4. Save. Boot it, then run `ip addr show` to find its `192.168.56.x` address.

> To revert after the demo: either re-import the OVA, or set Adapter 1 back to
> its previous mode. Note the current setting before you change it.

## 4. Find every machine's host-only IP

On each machine:
```bash
ip addr show        # look for the 192.168.56.x on the host-only adapter
```
Record them:
- Server (ApexGP): `192.168.56.____`
- Victim (host):   `192.168.56.____`   (often `.1`)
- Attacker (Kali): `192.168.56.____`

## 5. Confirm reachability

From Kali: `ping <server-ip>` and `ping <victim-ip>` should both work.

## 6. Interface name on Kali

`arp_spoof.py` / `sniff_cookie.py` take `-i`. Find the host-only interface on
Kali with `ip addr` (often `eth0` or `eth1` — the one with a `192.168.56.x`).

## 7. Pre-attack host check (victim)

On the host, confirm it will accept the poison (should print `0`s):
```bash
sysctl net.ipv4.conf.vboxnet0.arp_ignore net.ipv4.conf.all.arp_ignore
```
During the attack, watch the poison land:
```bash
watch -n1 "ip neigh show | grep <server-ip>"   # MAC flips to Kali's MAC
```
