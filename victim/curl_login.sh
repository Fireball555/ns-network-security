#!/usr/bin/env bash
# Optional traffic generator for the victim, if you prefer not to use a browser.
# Run on the VICTIM (host). Logs in and hits /account so the cookie crosses the
# wire for the sniffer to capture.
#
#   ./curl_login.sh 192.168.56.10 5000           # insecure (http)
#   ./curl_login.sh 192.168.56.10 5000 https     # secure   (https, -k for self-signed)
set -e
SERVER="${1:?usage: curl_login.sh <server-ip> <port> [https]}"
PORT="${2:-5000}"
SCHEME="${3:-http}"
K=""; [ "$SCHEME" = "https" ] && K="-k"

echo "[*] logging in to $SCHEME://$SERVER:$PORT ..."
curl $K -s -c /tmp/vaultly_cj.txt \
  -d "username=smaran&password=Password123!" \
  "$SCHEME://$SERVER:$PORT/login" >/dev/null

echo "[*] fetching /account (carries the session cookie) ..."
curl $K -s -b /tmp/vaultly_cj.txt "$SCHEME://$SERVER:$PORT/account" \
  | grep -E "Signed in as|balance-value" | sed 's/<[^>]*>//g; s/^ *//'
echo "[+] done — cookie has now crossed the wire."
