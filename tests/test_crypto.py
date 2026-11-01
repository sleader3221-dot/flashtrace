from __future__ import annotations

import hashlib
import random

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from flashtrace.crypto import (
    decrypt_nvs,
    flash_crypt,
    load_flash_key,
    load_public_key,
    parse_nvs_keys,
    sign_sbv2,
    verify_sbv2,
)
from tests.fixtures.nvs_cases import EXPECTED, ROWS, SIZE, parse, values
from tools.corpus.nvs_writer import build_nvs, encrypt_nvs, nvs_keys_image

RNG = random.Random(42)
KEY32 = RNG.randbytes(32)


@pytest.mark.parametrize("scheme", ["aes-xts", "esp32"])
@pytest.mark.parametrize("address", [0x0, 0x10000, 0x10010, 0x1F0])
def test_flash_round_trip(scheme: str, address: int) -> None:
    plain = RNG.randbytes(0x400)
    ct = flash_crypt(plain, address, KEY32, scheme, decrypt=False)  # type: ignore[arg-type]
    assert ct != plain
    assert flash_crypt(ct, address, KEY32, scheme) == plain  # type: ignore[arg-type]
    # position matters: the same ciphertext at another address does not decrypt
    assert flash_crypt(ct, address + 0x1000, KEY32, scheme) != plain  # type: ignore[arg-type]


def test_flash_crypt_conf_changes_esp32_output() -> None:
    plain = bytes(64)
    a = flash_crypt(plain, 0x8000, KEY32, "esp32", decrypt=False, flash_crypt_conf=0xF)
    b = flash_crypt(plain, 0x8000, KEY32, "esp32", decrypt=False, flash_crypt_conf=0x0)
    assert a != b


def test_key_normalisation() -> None:
    k16 = bytes(range(16))
    assert load_flash_key(k16, "aes-xts") == hashlib.sha256(k16).digest()
    k24 = bytes(range(24))
    assert load_flash_key(k24, "esp32") == k24 + k24[8:16]
    assert len(load_flash_key(bytes(64), "aes-xts")) == 64
    for bad, scheme in ((bytes(16), "esp32"), (bytes(24), "aes-xts"), (bytes(7), "aes-xts")):
        with pytest.raises(ValueError):
            load_flash_key(bad, scheme)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        flash_crypt(bytes(15), 0, KEY32, "aes-xts")


def test_nvs_encryption_round_trip_and_keys_partition() -> None:
    key = RNG.randbytes(64)
    plain = build_nvs(ROWS, SIZE)
    enc = encrypt_nvs(plain, key)
    assert enc[:64] == plain[:64]  # page header + bitmap stay plaintext
    assert parse(enc, nvs_keys_present=True).encrypted
    dec = decrypt_nvs(enc, key)
    assert dec == plain
    got = values(parse(dec))
    assert all(got[k] == v for k, v in EXPECTED.items())
    img = nvs_keys_image(key)
    assert parse_nvs_keys(img) == key
    bad = bytearray(img)
    bad[3] ^= 1
    assert parse_nvs_keys(bytes(bad)) is None
    assert parse_nvs_keys(b"\xff" * 0x1000) is None
    assert decrypt_nvs(enc, RNG.randbytes(64)) != plain


@pytest.mark.parametrize("kind", ["rsa", "p256", "p192"])
def test_sbv2_sign_and_verify(kind: str) -> None:
    if kind == "rsa":
        priv: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = rsa.generate_private_key(65537, 3072)
        other: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = rsa.generate_private_key(
            65537, 3072
        )
    else:
        curve = ec.SECP256R1() if kind == "p256" else ec.SECP192R1()
        priv, other = ec.generate_private_key(curve), ec.generate_private_key(curve)
    image = RNG.randbytes(5000)
    signed = sign_sbv2(image, priv)
    assert len(signed) % 4096 == 0
    [ok] = verify_sbv2(signed, priv.public_key(), 0x10000)
    assert ok.verified and ok.offset == 0x10000 + len(signed) - 4096
    [wrong] = verify_sbv2(signed, other.public_key())
    assert not wrong.verified and wrong.reason == "not signed by the supplied key"
    tampered = bytearray(signed)
    tampered[100] ^= 1
    [t] = verify_sbv2(bytes(tampered), priv.public_key())
    assert not t.verified and t.reason == "image digest mismatch"
    crc_bad = bytearray(signed)
    crc_bad[-4096 + 1196] ^= 1
    [c] = verify_sbv2(bytes(crc_bad), priv.public_key())
    assert not c.crc_ok and not c.verified


def test_load_public_key_forms() -> None:
    priv = ec.generate_private_key(ec.SECP256R1())
    pem_pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    der_pub = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_priv = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    for blob in (pem_pub, der_pub, pem_priv):
        assert load_public_key(blob).public_numbers() == priv.public_key().public_numbers()  # type: ignore[union-attr]
    with pytest.raises(ValueError):
        load_public_key(b"not a key")


def test_verify_sbv2_hostile_input() -> None:
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    assert verify_sbv2(b"", key) == []
    # magic bytes everywhere: blocks are found but none can verify
    assert all(not r.verified for r in verify_sbv2(b"\xe7\x02" * 4096, key))
    junk = bytearray(RNG.randbytes(8192))
    junk[4096:4098] = b"\xe7\x03"
    for r in verify_sbv2(bytes(junk), key):
        assert not r.verified
