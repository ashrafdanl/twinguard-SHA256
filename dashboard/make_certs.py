#!/usr/bin/env python3
"""
TwinGuard-SHA256: HTTPS certificates for the admin dashboard (LAN use)
=======================================================================
Creates a private certificate authority (CA) once, and a server certificate
for this machine signed by it. Install certs/twinguard-ca.crt on each admin
device once and browsers will trust the dashboard (padlock, no warnings).

    python3 dashboard/make_certs.py                   # this machine's names + IPs
    python3 dashboard/make_certs.py --ip 10.0.0.5     # add extra IPs / --dns names

Re-run it whenever this machine's IP address changes. The CA is reused, so
devices that already trust it keep working; only the server certificate is
replaced. Restart the dashboard afterwards.

Files (all in certs/, which is gitignored):
    twinguard-ca.crt   CA certificate  -> install on admin devices (safe to share)
    twinguard-ca.key   CA private key  -> NEVER share; can mint trusted certs
    server.crt/.key    dashboard certificate + key
"""

import argparse, datetime, ipaddress, os, socket, subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(BASE_DIR, "certs")
CA_CRT, CA_KEY = os.path.join(CERT_DIR, "twinguard-ca.crt"), os.path.join(CERT_DIR, "twinguard-ca.key")
SRV_CRT, SRV_KEY = os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key")


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def local_ipv4s():
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5).stdout.split()
    except Exception:
        out = []
    return [ip for ip in out if ":" not in ip]


def load_or_create_ca(now):
    if os.path.exists(CA_CRT) and os.path.exists(CA_KEY):
        with open(CA_KEY, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), None)
        with open(CA_CRT, "rb") as f:
            return key, x509.load_pem_x509_certificate(f.read()), False
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TwinGuard"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "TwinGuard Local CA")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    write_private(CA_KEY, key_pem(key))
    with open(CA_CRT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, True


def main():
    ap = argparse.ArgumentParser(description="Create HTTPS certificates for the TwinGuard dashboard")
    ap.add_argument("--ip", action="append", default=[], help="extra IP address to include (repeatable)")
    ap.add_argument("--dns", action="append", default=[], help="extra host name to include (repeatable)")
    args = ap.parse_args()

    os.makedirs(CERT_DIR, mode=0o700, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, ca_cert, ca_new = load_or_create_ca(now)

    host = socket.gethostname()
    dns = sorted({"localhost", host, f"{host}.local", *args.dns})
    ips = sorted({"127.0.0.1", *local_ipv4s(), *args.ip}, key=lambda s: ipaddress.ip_address(s))

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"TwinGuard Dashboard ({host})")]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=397))      # browser max for server certs
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                                         crl_sign=False, content_commitment=False, data_encipherment=False,
                                         key_agreement=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    write_private(SRV_KEY, key_pem(key))
    with open(SRV_CRT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"CA certificate : {CA_CRT} {'(NEW - install it on admin devices)' if ca_new else '(existing, reused)'}")
    print(f"Server cert    : {SRV_CRT} (valid until {cert.not_valid_after_utc:%Y-%m-%d})")
    print(f"  names        : {', '.join(dns)}")
    print(f"  IPs          : {', '.join(ips)}")
    print("Restart the dashboard to use the new certificate.")


if __name__ == "__main__":
    main()
