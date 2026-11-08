"""Mock PKI for the attack scenario (Person A).

Generates: root CA -> intermediate CA -> leaf cert for localhost, then REVOKES the
leaf and emits a CRL from the intermediate. All PEMs are written under outdir.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass
class PKI:
    root_cert_pem: str = ""
    root_key_pem: str = ""
    inter_cert_pem: str = ""
    inter_key_pem: str = ""
    leaf_cert_pem: str = ""
    leaf_key_pem: str = ""
    chain_pem: str = ""        # leaf + intermediate
    crl_pem: str = ""
    root_fingerprint: str = ""  # sha256 hex of root DER
    leaf_serial: str = ""       # hex
    root_spki_hash: str = ""
    inter_spki_hash: str = ""
    leaf_spki_hash: str = ""


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _pem_key(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def spki_hash(cert: x509.Certificate) -> str:
    """sha256 hex of the cert's SubjectPublicKeyInfo DER — the OneCRL-style identifier."""
    import hashlib
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca_cert(subject: x509.Name, issuer: x509.Name, key, issuer_key, days: int) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(issuer_key, hashes.SHA256()))


def build_pki(outdir: Path, cn_root: str = "eMudhra Demo Root CA") -> PKI:
    """Create root+intermediate+leaf(localhost); write all PEMs under outdir."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    pki = PKI()

    root_key = _key()
    root_cert = _ca_cert(_name(cn_root), _name(cn_root), root_key, root_key, 3650)
    inter_key = _key()
    inter_cert = _ca_cert(_name("eMudhra Demo Issuing CA"), root_cert.subject,
                          inter_key, root_key, 1825)
    leaf_key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    leaf = (x509.CertificateBuilder()
            .subject_name(_name("localhost"))
            .issuer_name(inter_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
                critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()),
                           critical=False)
            .sign(inter_key, hashes.SHA256()))

    import hashlib
    pki.root_cert_pem = _pem_cert(root_cert)
    pki.root_key_pem = _pem_key(root_key)
    pki.inter_cert_pem = _pem_cert(inter_cert)
    pki.inter_key_pem = _pem_key(inter_key)
    pki.leaf_cert_pem = _pem_cert(leaf)
    pki.leaf_key_pem = _pem_key(leaf_key)
    pki.chain_pem = pki.leaf_cert_pem + pki.inter_cert_pem
    pki.root_fingerprint = hashlib.sha256(
        root_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    pki.leaf_serial = format(leaf.serial_number, "x")
    pki.root_spki_hash = spki_hash(root_cert)
    pki.inter_spki_hash = spki_hash(inter_cert)
    pki.leaf_spki_hash = spki_hash(leaf)

    (outdir / "root.crt").write_text(pki.root_cert_pem)
    (outdir / "root.key").write_text(pki.root_key_pem)
    (outdir / "inter.crt").write_text(pki.inter_cert_pem)
    (outdir / "inter.key").write_text(pki.inter_key_pem)
    (outdir / "leaf.crt").write_text(pki.leaf_cert_pem)
    (outdir / "leaf.key").write_text(pki.leaf_key_pem)
    (outdir / "chain.pem").write_text(pki.chain_pem)
    (outdir / "pki.json").write_text(__import__("json").dumps({
        "root_fingerprint": pki.root_fingerprint, "leaf_serial": pki.leaf_serial,
        "root_spki_hash": pki.root_spki_hash, "inter_spki_hash": pki.inter_spki_hash,
        "leaf_spki_hash": pki.leaf_spki_hash}, indent=2))
    return pki


def revoke_leaf(pki: PKI, outdir: Path) -> str:
    """Mark the leaf revoked on the intermediate; write + return the new CRL PEM."""
    outdir = Path(outdir)
    inter_key = serialization.load_pem_private_key(pki.inter_key_pem.encode(), password=None)
    inter_cert = x509.load_pem_x509_certificate(pki.inter_cert_pem.encode())
    now = datetime.datetime.now(datetime.timezone.utc)
    revoked = (x509.RevokedCertificateBuilder()
               .serial_number(int(pki.leaf_serial, 16))
               .revocation_date(now)
               .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
               .build())
    crl = (x509.CertificateRevocationListBuilder()
           .issuer_name(inter_cert.subject)
           .last_update(now - datetime.timedelta(minutes=5))
           .next_update(now + datetime.timedelta(days=30))
           .add_revoked_certificate(revoked)
           .sign(inter_key, hashes.SHA256()))
    crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()
    (outdir / "crl.pem").write_text(crl_pem)
    pki.crl_pem = crl_pem
    return crl_pem


def load_pki(pki_dir: Path) -> PKI:
    """Reload a PKI previously written by build_pki."""
    import json
    pki_dir = Path(pki_dir)
    pki = PKI(
        root_cert_pem=(pki_dir / "root.crt").read_text(),
        root_key_pem=(pki_dir / "root.key").read_text(),
        inter_cert_pem=(pki_dir / "inter.crt").read_text(),
        inter_key_pem=(pki_dir / "inter.key").read_text(),
        leaf_cert_pem=(pki_dir / "leaf.crt").read_text(),
        leaf_key_pem=(pki_dir / "leaf.key").read_text(),
        chain_pem=(pki_dir / "chain.pem").read_text(),
        crl_pem=(pki_dir / "crl.pem").read_text() if (pki_dir / "crl.pem").exists() else "",
    )
    meta = json.loads((pki_dir / "pki.json").read_text())
    pki.root_fingerprint = meta["root_fingerprint"]
    pki.leaf_serial = meta["leaf_serial"]
    pki.root_spki_hash = meta["root_spki_hash"]
    pki.inter_spki_hash = meta["inter_spki_hash"]
    pki.leaf_spki_hash = meta["leaf_spki_hash"]
    return pki


def mint_attacker_cert(pki_dir: Path, hostname: str = "bank.local") -> tuple[Path, Path, Path]:
    """Simulated MITM: a FRESH leaf cert minted by the compromised intermediate.

    Unlike the demo leaf, this serial was never revoked, so it is NOT on the CRL —
    CRL-aware clients accept it too. Only distrusting the root stops it.
    Writes attacker.crt / attacker.key / attacker-chain.pem (leaf+inter) under pki_dir.
    Returns (cert_path, key_path, chain_path).
    """
    import ipaddress
    pki_dir = Path(pki_dir)
    pki = load_pki(pki_dir)
    inter_key = serialization.load_pem_private_key(pki.inter_key_pem.encode(), password=None)
    inter_cert = x509.load_pem_x509_certificate(pki.inter_cert_pem.encode())
    atk_key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    atk = (x509.CertificateBuilder()
           .subject_name(_name(hostname))
           .issuer_name(inter_cert.subject)
           .public_key(atk_key.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(now - datetime.timedelta(minutes=5))
           .not_valid_after(now + datetime.timedelta(days=90))
           .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
           .add_extension(x509.SubjectAlternativeName(
               [x509.DNSName(hostname), x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
           .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                          critical=False)
           .add_extension(x509.SubjectKeyIdentifier.from_public_key(atk_key.public_key()),
                          critical=False)
           .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
               inter_key.public_key()), critical=False)
           .sign(inter_key, hashes.SHA256()))
    cert_path = pki_dir / "attacker.crt"
    key_path = pki_dir / "attacker.key"
    chain_path = pki_dir / "attacker-chain.pem"
    cert_path.write_text(_pem_cert(atk))
    key_path.write_text(_pem_key(atk_key))
    chain_path.write_text(_pem_cert(atk) + pki.inter_cert_pem)
    return cert_path, key_path, chain_path
