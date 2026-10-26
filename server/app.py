"""
Vaultly — a deliberately vulnerable demo login app (NETWORK SECURITY LAB).

This is NOT a real service. It is a fictional demo app used ONLY inside an
isolated VirtualBox host-only network to demonstrate session hijacking and
its mitigations. Do not deploy it anywhere reachable from a real network.

Two modes:
  --insecure  (default)  HTTP, cookie encrypted but NOT bound to client,
                         no Secure/HttpOnly flags  -> vulnerable to replay
  --secure               HTTPS (self-signed), cookie bound to client IP,
                         Secure + HttpOnly + SameSite flags  -> replay fails

Run on the SERVER vm (ApexGP):
    python3 app.py --insecure --host 192.168.56.10
    python3 app.py --secure   --host 192.168.56.10
"""
import argparse
import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask, request, redirect, url_for, make_response, render_template, abort
)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Demo "database". Dummy credentials only — nothing real.
# ---------------------------------------------------------------------------
USERS = {
    "smaran": {"password": "Password123!", "name": "Ram Smaran",
               "balance": "₹ 48,250.00", "acct": "VAULT-0042-7781"},
}

# A fixed key so the cookie is reproducible across restarts in the lab.
# The ATTACKER never needs this key — that is the whole point of the demo.
# The server encrypts the session; the attacker just REPLAYS the blob.
FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(b"vaultly-lab-demo-key").digest())
fernet = Fernet(FERNET_KEY)

COOKIE_NAME = "vaultly_session"


def make_session_cookie(username: str, client_ip: str, bind_ip: bool) -> str:
    """Build the encrypted session token.

    In --secure mode we bind the token to the client's IP, so a token stolen
    and replayed from a different machine (the attacker) is rejected.
    """
    payload = {"user": username}
    if bind_ip:
        payload["ip"] = client_ip
    raw = json.dumps(payload).encode()
    return fernet.encrypt(raw).decode()


def read_session_cookie(token: str, client_ip: str, bind_ip: bool):
    try:
        raw = fernet.decrypt(token.encode())
    except InvalidToken:
        return None
    data = json.loads(raw)
    if bind_ip:
        # Reject a token presented from an IP other than the one it was
        # issued to. This is what breaks the replay attack.
        if data.get("ip") != client_ip:
            return None
    return data.get("user")


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u in USERS and USERS[u]["password"] == p:
            token = make_session_cookie(u, request.remote_addr, app.config["BIND_IP"])
            resp = make_response(redirect(url_for("account")))
            resp.set_cookie(
                COOKIE_NAME, token,
                httponly=app.config["SECURE"],   # blocks document.cookie theft
                secure=app.config["SECURE"],      # only sent over HTTPS
                samesite="Strict" if app.config["SECURE"] else None,
            )
            return resp
        error = "Invalid username or password."
    return render_template("login.html", error=error, mode=app.config["MODE"])


@app.route("/account")
def account():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return redirect(url_for("login"))
    user = read_session_cookie(token, request.remote_addr, app.config["BIND_IP"])
    if not user:
        # Token invalid, tampered, or (in secure mode) presented from the
        # wrong IP — treat as not logged in.
        return render_template("denied.html", mode=app.config["MODE"]), 403
    return render_template("account.html", u=USERS[user], mode=app.config["MODE"])


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie(COOKIE_NAME)
    return resp


def generate_self_signed_cert(certfile, keyfile):
    """Create a throwaway self-signed cert for --secure mode."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vaultly.lab")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    with open(keyfile, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--insecure", action="store_true", help="HTTP, replayable (default)")
    g.add_argument("--secure", action="store_true", help="HTTPS + IP-bound cookie")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (use the host-only IP)")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    secure = args.secure
    app.config["SECURE"] = secure
    app.config["BIND_IP"] = secure
    app.config["MODE"] = "SECURE (HTTPS, IP-bound cookie)" if secure else "INSECURE (HTTP, replayable)"

    ssl_ctx = None
    if secure:
        here = os.path.dirname(os.path.abspath(__file__))
        cert, key = os.path.join(here, "cert.pem"), os.path.join(here, "key.pem")
        if not (os.path.exists(cert) and os.path.exists(key)):
            print("[*] generating self-signed cert ...")
            generate_self_signed_cert(cert, key)
        ssl_ctx = (cert, key)
        scheme = "https"
    else:
        scheme = "http"

    print(f"[*] Vaultly demo  mode={app.config['MODE']}")
    print(f"[*] serving on {scheme}://{args.host}:{args.port}  (login: smaran / Password123!)")
    app.run(host=args.host, port=args.port, ssl_context=ssl_ctx, debug=False)
