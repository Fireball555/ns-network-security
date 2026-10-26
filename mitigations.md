# Mitigations — mapped to the step each one breaks

The attack is a chain. Breaking **any** link stops it; a real system uses
defence in depth and breaks several.

| # | Attack step | Defence | How it breaks the step |
|---|---|---|---|
| 1 | Get in the middle (ARP poison) | **Static ARP entries** | Critical IP→MAC mappings are pinned; forged replies are ignored. |
| 1 | Get in the middle (ARP poison) | **Dynamic ARP Inspection (DAI)** + DHCP snooping | Managed switch validates ARP replies against a trusted binding table and drops spoofed ones. |
| 1 | Get in the middle (ARP poison) | **arpwatch / detection** | Alerts when one MAC suddenly claims two IPs (or an IP's MAC changes) — the classic fingerprint. |
| 2 | Sniff the cookie off the wire | **HTTPS / TLS** | Traffic is encrypted end-to-end; the attacker sees only ciphertext and can't locate or read the cookie. |
| 2 | Sniff the cookie off the wire | **HttpOnly cookie flag** | Blocks `document.cookie` theft via injected JS (a different capture path). |
| 2 | Sniff the cookie off the wire | **Secure cookie flag** | Browser refuses to send the cookie over plain HTTP, so it never travels in cleartext. |
| 3 | Replay the cookie to log in | **Session–client binding** (IP / fingerprint) | Token is tied to the client it was issued to; a replay from the attacker's IP is rejected (403). |
| 3 | Replay the cookie to log in | **Short expiry + rotation** | A stolen token is valid only briefly; rotating the session ID on privilege change limits reuse. |
| 3 | Replay the cookie to log in | **SameSite + re-auth for sensitive actions** | Limits cross-context use and forces a password/OTP for high-value operations. |

## What this project demonstrates directly

- **HTTPS (step 2 fix):** in `--secure` mode the sniffer gets nothing readable.
- **Session–IP binding (step 3 fix):** `replay.py --https` returns **403** —
  the token is valid but refused from the attacker's IP.
- **HttpOnly / Secure / SameSite:** set on the cookie in `--secure` mode
  (`server/app.py`).

## The key teaching point

> Self-encrypting the payload over HTTP does **not** help, because the attack is
> **replay of a bearer token**, not decryption. The fix is **transport security
> (TLS)** to stop the capture, plus **session binding** to stop reuse if a token
> ever leaks. Confidentiality of the cookie's contents is the wrong layer for
> this threat.
