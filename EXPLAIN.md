# Theory & Viva Prep

## 1. How machines talk on a LAN

Every machine has two addresses:
- **IP address** (`192.168.56.10`) — logical, used to route across networks.
- **MAC address** (`08:00:27:ab:cd:ef`) — physical, burned into the NIC, used
  to actually deliver a frame on the local wire.

To send to an IP on the same LAN, a machine needs that IP's MAC. It finds it
with **ARP**.

## 2. ARP (Address Resolution Protocol)

- Host broadcasts: *"Who has 192.168.56.10? Tell me your MAC."*
- The owner replies: *"That's me, MAC = 08:00:27:…"*
- The host caches the answer in its **ARP cache** (`ip neigh` / `arp -a`).

**The flaw:** ARP has **no authentication**. Any machine can reply, and a
machine can send an **unsolicited (gratuitous) ARP reply** that the receiver
will believe and cache. *Whoever answers is trusted.*

## 3. The attack — ARP poisoning / MITM

The attacker sends two continuous lies:
- To the **victim**: "I am the server."
- To the **server**: "I am the victim."

Both caches now point to the attacker's MAC, so all traffic between them flows
**through the attacker** = man-in-the-middle.

```
Normal:    Victim ───────────────► Server
Poisoned:  Victim ──► [Attacker] ──► Server
                        ▲ reads / relays everything
```

The attacker enables **IP forwarding** so it relays the traffic onward —
otherwise the victim loses connectivity and notices.

**Why the switch doesn't save you:** a switch forwards each frame only to the
port owning the destination MAC. But poisoning makes the victim *willingly*
address its frames to the attacker's MAC, so the switch correctly delivers them
to the attacker. The switch did its job; the lie happened one layer up (L2 ARP),
not at the switch's forwarding table.

## 4. Session cookies and the bearer-token problem

After login, the server gives the browser a **session cookie**. Every later
request carries it, so the user stays logged in. A session cookie is a
**bearer token**: *whoever holds it is treated as that user.*

This is the key insight for the viva:

> **Encrypting the cookie's contents protects *what is inside* it. It does
> nothing about the fact that holding the cookie = being you.** The attacker
> captures the encrypted blob and **replays it unchanged**. The server (which
> has the key) decrypts it, sees a valid session, and logs the attacker in.
> This is a **replay attack** — no decryption by the attacker required.

So "I encrypted the username/password myself, so HTTP is fine" is **false**.
The attacker never needed to read it.

## 4b. "It looks secure" is not "it is secure"

The demo login page is deliberately dressed up like a real bank: a padlock and
"Secured connection", "256-bit end-to-end encryption", "SOC 2 Type II
certified", SSL / PCI DSS / "Verified" badges, a "Sign in securely" button.
**Every one of those is just pixels** — text and icons the developer typed into
the HTML. They are served over plain HTTP and the session is still stolen and
replayed.

Security is a property of the **transport and the protocol**, not of the UI:

- A padlock *drawn on the page* means nothing. The only padlock that matters is
  the **browser's address-bar padlock**, which reflects a real TLS connection
  with a valid certificate — and even that only proves the channel is encrypted
  and the server's identity is verified, not that the site is honest.
- Trust badges ("SOC 2", "PCI DSS", "256-bit") are unverifiable claims. An
  attacker's phishing page can copy them pixel-for-pixel.
- The real question is never "does it look safe?" but "is the connection
  `https://` with a valid cert, and is the session protected against theft and
  replay?"

**Viva line:** *A professional-looking login page is trivial to build; looking
trustworthy and being secure are unrelated. This page shows every trust signal
a bank would — and is hijacked anyway, because it runs over HTTP. Users (and
developers) must judge security by the transport, not the visuals.*

## 5. Why HTTPS/TLS is the real fix (not self-encryption)

Hand-rolled encryption over HTTP still fails on four counts:
1. **Replay** — the stolen token is reusable (the big one).
2. **No server authentication** — over HTTP you can't prove you're talking to
   the real server; a MITM can impersonate it.
3. **No integrity** — without a MAC, the attacker can tamper.
4. **No forward secrecy** — one key leak exposes all past captures.

TLS adds: a **fresh session key per connection** (via the handshake), a
**certificate** that proves server identity, and **built-in integrity**. That
is why the sniffer sees only ciphertext and can't even locate the cookie.

Transport encryption solves confidentiality on the wire. **Session binding**
(tying the token to the client) solves the replay even if a token does leak.

---

## Likely viva questions

**Q: Why does ARP spoofing work?**
ARP has no authentication; receivers cache any reply, including unsolicited
ones. The attacker forges replies to map the victim's/server's IP to its own MAC.

**Q: You encrypted the cookie — how is it still stolen?**
It's a bearer token. The attacker replays the encrypted blob as-is; the server
decrypts it and accepts it. Confidentiality of the payload is irrelevant to
replay.

**Q: Doesn't a switch prevent sniffing?**
No. Poisoning makes the victim send frames to the attacker's MAC voluntarily, so
the switch delivers them to the attacker. ARP operates below the switch's logic.

**Q: Why enable IP forwarding on the attacker?**
So the victim's traffic is relayed to the real server and connectivity isn't
broken — the attack stays stealthy.

**Q: How does secure mode stop the replay specifically?**
The session token is bound to the IP it was issued to. A token replayed from the
attacker's IP fails the check → HTTP 403. HTTPS additionally stops the capture
in the first place.

**Q: Difference between ARP spoofing and MAC flooding?**
ARP spoofing poisons caches to redirect specific traffic (targeted MITM). MAC
flooding overflows the switch's CAM table so it fails open and floods all ports
(broad sniffing). Different mechanisms, both L2.

**Q: Real-world mitigations at scale?**
Dynamic ARP Inspection (DAI) with DHCP snooping on managed switches, 802.1X,
static ARP for critical hosts, and end-to-end TLS so interception yields nothing.
