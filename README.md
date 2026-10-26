# ARP Spoofing → Session Hijacking → Mitigation (Network Security Lab)

A self-contained lab that demonstrates a **man-in-the-middle session hijack**
and the defences that stop it. Built for the Network Security course
(ARP spoofing, session hijacking, TLS, and their countermeasures).

> ⚠️ **Lab use only.** Everything runs on an **isolated VirtualBox host-only
> network** (`vboxnet0`) with no internet exposure, using **your own machines**
> and **dummy credentials**. `Vaultly` is a **fictional demo app**, not a clone
> of any real service. Running ARP spoofing against networks or machines you do
> not own is illegal.

## The idea in one line

> ARP has no authentication, so the attacker reroutes traffic through himself,
> reads the session cookie off the wire, and **replays** it to log in as the
> victim — *without ever knowing the password or the encryption key*. HTTPS +
> IP-bound sessions break the whole chain.

## Roles

| Machine | Role | Example IP (host-only) |
|---|---|---|
| **ApexGP VM** | Server — runs the Vaultly demo app | `192.168.56.10` |
| **Host (your laptop)** | Victim — logs into Vaultly in a browser | `192.168.56.1` / `.101` |
| **Kali VM** | Attacker — ARP spoof, sniff, replay | `192.168.56.20` |

Find each machine's host-only IP with `ip addr show` (Linux) and plug the real
values into the commands below. See `setup_vms.md` for VM networking.

## Layout

```
server/      app.py + templates + css   (runs on ApexGP)
attacker/    arp_spoof.py, sniff_cookie.py, replay.py   (runs on Kali)
victim/      curl_login.sh              (optional traffic generator)
EXPLAIN.md   theory + viva Q&A
mitigations.md   each fix mapped to the step it breaks
setup_vms.md VirtualBox networking + OVA notes
```

## Install (on ApexGP and Kali)

```bash
pip install -r requirements.txt          # or: sudo apt install python3-scapy python3-flask
```

---

## PART 1 — The attack (insecure mode)

**1. Server (ApexGP):**
```bash
cd server
python3 app.py --insecure --host 192.168.56.10
```

**2. Attacker (Kali) — get in the middle:**
```bash
sudo sysctl -w net.ipv4.ip_forward=1          # keep victim's traffic flowing
sudo python3 arp_spoof.py --victim 192.168.56.1 --server 192.168.56.10 -i eth0
```
Leave it running. On the **host**, confirm the poison landed:
```bash
ip neigh show | grep 192.168.56.10            # MAC should now be KALI's MAC
```

**3. Attacker (Kali) — sniff, in a second terminal:**
```bash
sudo python3 sniff_cookie.py -i eth0 --port 5000
```

**4. Victim (host):** open `http://192.168.56.10:5000`, log in with
`smaran / Password123!`. The sniffer prints the captured cookie and saves it.

**5. Attacker (Kali) — hijack:**
```bash
python3 replay.py --server 192.168.56.10 --port 5000
```
→ `HIJACK SUCCESSFUL — logged in as the victim`. The attacker is now inside the
account **without the password and without decrypting anything**.

---

## PART 2 — The fix (secure mode)

**Server (ApexGP):**
```bash
python3 app.py --secure --host 192.168.56.10
```
Victim logs in again at **`https://`**`192.168.56.10:5000` (accept the
self-signed cert warning — in production this would be a real CA cert).

Now re-run the attack:
- **Sniffer** sees only encrypted TLS bytes — no cookie to grab.
- Even if you hand `replay.py` a token, run it with `--https`:
  ```bash
  python3 replay.py --server 192.168.56.10 --port 5000 --https
  ```
  → `HIJACK BLOCKED (HTTP 403)` — the session is bound to the victim's IP, so a
  replay from the attacker's IP is refused.

---

## What each defence stops

See `mitigations.md`. Short version: **HTTPS** kills the sniff, **IP-bound
sessions** + `HttpOnly`/`Secure` kill the replay, **static ARP / Dynamic ARP
Inspection** kill the poisoning, **arpwatch** detects it.

## Cleanup

Stop `arp_spoof.py` with **Ctrl+C** — it restores both ARP caches automatically.
Then `sudo sysctl -w net.ipv4.ip_forward=0` on Kali.
