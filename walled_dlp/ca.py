"""Per-machine, name-constrained root CA.

The private key is generated locally and never leaves the machine. The CA
carries an X.509 NameConstraints extension that only permits the ChatGPT /
Perplexity / upload-storage domains, so even if the key leaked it could not be
used to impersonate any other site (browsers enforce name constraints).
"""
from __future__ import annotations

import datetime
import os
import platform
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .config import Config, app_home

CA_CN_PREFIX = "WALLED DLP Local CA"


def ca_dir() -> Path:
    d = app_home() / "ca"
    d.mkdir(parents=True, exist_ok=True)
    return d


def mitm_ca_file() -> Path:
    return ca_dir() / "mitmproxy-ca.pem"      # key + cert (read by mitmproxy)


def public_cert_file() -> Path:
    return ca_dir() / "walled-dlp-ca.pem"     # cert only (installed in trust store)


def ca_exists() -> bool:
    return mitm_ca_file().exists() and public_cert_file().exists()


def load_ca_cert() -> x509.Certificate:
    return x509.load_pem_x509_certificate(public_cert_file().read_bytes())


def ca_common_name() -> str:
    return f"{CA_CN_PREFIX} ({platform.node() or 'host'})"[:64]


def generate_ca(cfg: Config, years: int = 3) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name()),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WALLED DLP"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    permitted = [x509.DNSName(d) for d in cfg.constraint_domains()]
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                          encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    f = mitm_ca_file()
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key_pem + cert_pem)
    public_cert_file().write_bytes(cert_pem)
    (ca_dir() / "walled-dlp-ca.cer").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    # Drop any leaf certs mitmproxy may have cached for an older CA.
    for stale in ("mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.p12", "mitmproxy-ca.p12"):
        (ca_dir() / stale).unlink(missing_ok=True)
    return public_cert_file()


def fingerprint() -> str:
    return load_ca_cert().fingerprint(hashes.SHA256()).hex(":").upper()


# --------------------------------------------------------------------------
# Trust store install / removal
# --------------------------------------------------------------------------
def _login_keychain() -> str:
    return str(Path.home() / "Library" / "Keychains" / "login.keychain-db")


def install_trust() -> None:
    cert = public_cert_file()
    if sys.platform == "darwin":
        # Login keychain + user trust setting: macOS shows its own password prompt.
        subprocess.run(["security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl",
                        "-k", _login_keychain(), str(cert)], check=True)
    elif sys.platform.startswith("win"):
        subprocess.run(["certutil", "-user", "-addstore", "Root", str(ca_dir() / "walled-dlp-ca.cer")], check=True)
    else:
        print("Linux: add", cert, "to your browser/NSS trust store, e.g.\n"
              f"  certutil -d sql:$HOME/.pki/nssdb -A -t 'C,,' -n 'WALLED DLP' -i {cert}")


def uninstall_trust() -> None:
    if not public_cert_file().exists():
        return
    if sys.platform == "darwin":
        subprocess.run(["security", "remove-trusted-cert", str(public_cert_file())], check=False)
        sha1 = load_ca_cert().fingerprint(hashes.SHA1()).hex().upper()
        subprocess.run(["security", "delete-certificate", "-Z", sha1, _login_keychain()], check=False)
    elif sys.platform.startswith("win"):
        serial = format(load_ca_cert().serial_number, "x")
        subprocess.run(["certutil", "-user", "-delstore", "Root", serial], check=False)
