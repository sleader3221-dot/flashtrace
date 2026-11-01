"""Deterministic secret / indicator detectors over byte regions.

Each detector returns :class:`SecretMatch` objects with region-relative offsets;
rules translate them to dump Evidence through :meth:`ScanRegion.evidence`.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass

from cryptography import x509

PEM_PRIVATE_KEY = re.compile(
    rb"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----"
    rb"[A-Za-z0-9+/=\r\n:,\- ]{16,16384}?"
    rb"-----END \1-----"
)
PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n ]{16,16384}?-----END CERTIFICATE-----"
)
AWS_KEY_ID = re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
GENERIC_TOKEN = re.compile(
    rb"(?<![A-Za-z0-9_\-+/])[A-Za-z0-9_\-+/]{32,256}={0,2}(?![A-Za-z0-9_\-])"
)
MQTT_URI = re.compile(rb"mqtts?://[^\s\"'<>\x00-\x1f\x7f-\xff]{3,200}")
MQTT_PORT = re.compile(
    rb"(?<![A-Za-z0-9.\-])[A-Za-z0-9][A-Za-z0-9.\-]{1,200}:(?:1883|8883)(?![0-9])"
)
URL = re.compile(rb"https?://[^\s\"'<>\x00-\x1f\x7f-\xff]{3,500}")
CREDENTIAL = re.compile(
    rb"(?i)(?<![A-Za-z0-9])(pass(?:word|wd)?|pwd|passphrase|secret|api[_-]?key|auth[_-]?token|token)"
    rb"[\"']?\s*[:=]\s*[\"']?([^\s\"',;&<>\x00-\x1f\x7f-\xff]{4,128})"
)
URL_USERINFO = re.compile(
    rb"[a-z][a-z0-9+.\-]{1,15}://([^\s:/@\"'\x00]{1,64}):([^\s/@\"'\x00]{3,64})@"
)
DER_SEQ = re.compile(rb"\x30\x82(?=..\x30[\x81\x82])", re.S)  # Certificate{ tbsCertificate

GENERIC_TOKEN_MIN_ENTROPY = 4.0  # bits per character
PLACEHOLDERS = {
    b"%s",
    b"null",
    b"none",
    b"changeme",
    b"xxxx",
    b"****",
    b"<password>",
    b"password",
    b"your_password",
}
MAX_DER_ATTEMPTS = 256


@dataclass(frozen=True)
class SecretMatch:
    kind: str  # "pem_private_key" | "pem_cert" | "der_cert" | "aws_key_id" | ...
    rel: int  # offset within the scanned region
    length: int
    value: bytes  # the secret / indicator bytes (unredacted)
    context: str = ""  # e.g. key name for credentials, cert subject


def char_entropy(s: bytes) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def find_private_keys(data: bytes) -> Iterator[SecretMatch]:
    for m in PEM_PRIVATE_KEY.finditer(data):
        label = m.group(1).decode()
        yield SecretMatch("pem_private_key", m.start(), m.end() - m.start(), m.group(), label)


def find_certificates(data: bytes) -> Iterator[SecretMatch]:
    for m in PEM_CERT.finditer(data):
        subject = ""
        try:
            subject = x509.load_pem_x509_certificate(m.group()).subject.rfc4514_string()
        except Exception:  # hostile input must never crash the scan
            subject = "(unparseable PEM)"
        yield SecretMatch("pem_cert", m.start(), m.end() - m.start(), m.group(), subject)
    attempts = 0
    for m in DER_SEQ.finditer(data):
        if attempts >= MAX_DER_ATTEMPTS:
            break
        start = m.start()
        length = int.from_bytes(data[start + 2 : start + 4], "big") + 4
        if length < 64 or start + length > len(data):
            continue
        attempts += 1
        blob = data[start : start + length]
        der_subject = _der_subject(blob)
        if der_subject is not None:
            yield SecretMatch("der_cert", start, length, blob, der_subject)


def _der_subject(blob: bytes) -> str | None:
    try:
        return str(x509.load_der_x509_certificate(blob).subject.rfc4514_string())
    except Exception:  # hostile input must never crash the scan
        return None


def find_aws_keys(data: bytes) -> Iterator[SecretMatch]:
    for m in AWS_KEY_ID.finditer(data):
        yield SecretMatch("aws_key_id", m.start(), m.end() - m.start(), m.group())


def _looks_random_token(tok: bytes) -> bool:
    core = tok.rstrip(b"=")
    if len(core) < 32:
        return False
    if re.fullmatch(rb"[0-9a-fA-F]+", core):
        return False  # hex digests / hex dumps: too common to flag generically
    has = (
        re.search(rb"[a-z]", core) is not None,
        re.search(rb"[A-Z]", core) is not None,
        re.search(rb"[0-9]", core) is not None,
    )
    if not all(has):
        return False
    return char_entropy(core) >= GENERIC_TOKEN_MIN_ENTROPY


PEM_ANY_BLOCK = re.compile(
    rb"-----BEGIN [A-Z0-9 ]{3,40}-----.{0,16384}?-----END [A-Z0-9 ]{3,40}-----", re.S
)


DATA_URI_PREFIX = re.compile(rb"data:[A-Za-z0-9.+/-]{1,64}(?:;[A-Za-z0-9=.-]{1,32})*;base64,$")


def _pem_spans(data: bytes) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in PEM_ANY_BLOCK.finditer(data)]


def find_generic_tokens(data: bytes) -> Iterator[SecretMatch]:
    spans = _pem_spans(data) if b"-----BEGIN " in data else []
    for m in GENERIC_TOKEN.finditer(data):
        tok = m.group()
        if AWS_KEY_ID.fullmatch(tok) or not _looks_random_token(tok):
            continue
        if any(a <= m.start() < b for a, b in spans):
            continue  # base64 body of a PEM block: owned by SEC.PRIVATE_KEY / SEC.CERT
        if DATA_URI_PREFIX.search(data[max(0, m.start() - 80) : m.start()]):
            continue  # payload of a data: URI (embedded image/font), encoded content
        yield SecretMatch("generic_token", m.start(), len(tok), tok)


def find_mqtt(data: bytes) -> Iterator[SecretMatch]:
    seen: set[int] = set()
    for m in MQTT_URI.finditer(data):
        seen.update(range(m.start(), m.end()))
        yield SecretMatch("mqtt_uri", m.start(), m.end() - m.start(), m.group())
    for m in MQTT_PORT.finditer(data):
        host = m.group().split(b":")[0]
        if m.start() in seen or (b"." not in host and host != b"localhost"):
            continue
        yield SecretMatch("mqtt_host_port", m.start(), m.end() - m.start(), m.group())


def find_urls(data: bytes) -> Iterator[SecretMatch]:
    for m in URL.finditer(data):
        yield SecretMatch("url", m.start(), m.end() - m.start(), m.group().rstrip(b".,);"))


def find_credentials(data: bytes) -> Iterator[SecretMatch]:
    for m in CREDENTIAL.finditer(data):
        val = m.group(2)
        if val.lower() in PLACEHOLDERS or val.startswith((b"%", b"$", b"{")):
            continue
        yield SecretMatch(
            "credential_assignment",
            m.start(2),
            len(val),
            val,
            m.group(1).decode(errors="replace").lower(),
        )
    for m in URL_USERINFO.finditer(data):
        val = m.group(2)
        if val.lower() in PLACEHOLDERS:
            continue
        yield SecretMatch(
            "url_userinfo",
            m.start(2),
            len(val),
            val,
            "user=" + m.group(1).decode(errors="replace"),
        )


SECRETISH_KEY = re.compile(
    r"(?i)(pass|pswd|pwd|secret|token|api.?key|apikey|cred|auth|private|psk|pmk|cert|\bkey\b)"
)


def looks_like_secret_value(value: bytes) -> str | None:
    """Return the detector kind if ``value`` itself looks like a secret."""
    for fn in (find_private_keys, find_aws_keys, find_generic_tokens, find_credentials):
        for m in fn(value):
            return m.kind
    return None
