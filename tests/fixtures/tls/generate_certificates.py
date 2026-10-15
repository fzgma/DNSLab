"""Regenerate PUBLIC TEST KEYS and certificates; never use them outside tests.

Requires the optional cryptography package only when regenerating fixtures.
Running the integration tests requires only the Python standard library.
"""

from datetime import datetime, timezone
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT = Path(__file__).resolve().parent
START = datetime(2020, 1, 1, tzinfo=timezone.utc)
END = datetime(2040, 1, 1, tzinfo=timezone.utc)
CRL_URL = "http://127.0.0.1:18453/dnslab-test-root.crl"


def write_key(name, key):
    (ROOT / name).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


def write_certificate(name, certificate):
    (ROOT / name).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def generate():
    authority_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    authority_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "DNSLab PUBLIC TEST ONLY Root CA")])
    authority = (x509.CertificateBuilder().subject_name(authority_name)
        .issuer_name(authority_name).public_key(authority_key.public_key())
        .serial_number(1000).not_valid_before(START).not_valid_after(END)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True,
                                     False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
            authority_key.public_key()), critical=False)
        .sign(authority_key, hashes.SHA256()))
    write_certificate("ca.pem", authority)
    crl = (x509.CertificateRevocationListBuilder().issuer_name(authority_name)
        .last_update(START).next_update(END)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            authority_key.public_key()), critical=False)
        .add_extension(x509.CRLNumber(1), critical=False)
        .sign(authority_key, hashes.SHA256()))
    (ROOT / "root.crl").write_bytes(crl.public_bytes(serialization.Encoding.DER))
    for number, name, names, expires in (
        (1001, "server", [x509.DNSName("localhost"),
                           x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                           x509.IPAddress(ipaddress.ip_address("::1"))], END),
        (1002, "wrong-host", [x509.DNSName("wrong.example.test")], END),
        (1003, "expired", [x509.DNSName("localhost"),
                            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
         datetime(2021, 1, 1, tzinfo=timezone.utc)),
    ):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(
                NameOID.COMMON_NAME, "DNSLab PUBLIC TEST ONLY " + name)]))
            .issuer_name(authority_name).public_key(key.public_key())
            .serial_number(number).not_valid_before(START).not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False,
                                         False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(CRL_URL)],
                relative_name=None, reasons=None, crl_issuer=None)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                authority_key.public_key()), critical=False)
            .sign(authority_key, hashes.SHA256()))
        write_key(name + ".key", key)
        write_certificate(name + ".pem", certificate)


if __name__ == "__main__":
    generate()
