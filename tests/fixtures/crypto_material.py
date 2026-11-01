"""Throw-away key/cert material generated at test time (never committed)."""

from __future__ import annotations

import datetime
from functools import cache

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@cache
def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def pem_private_key() -> bytes:
    return _key().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@cache
def _cert() -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "flashtrace-test.invalid")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_key().public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(_key(), hashes.SHA256())
    )


def pem_cert() -> bytes:
    return _cert().public_bytes(serialization.Encoding.PEM)


def der_cert() -> bytes:
    return _cert().public_bytes(serialization.Encoding.DER)
