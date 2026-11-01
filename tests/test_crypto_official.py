"""CI: FlashTrace crypto must match espsecure (esptool 5.1.0) and nvs_partition_gen 0.2.0."""

from __future__ import annotations

import random
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from flashtrace.crypto import decrypt_nvs, flash_crypt, load_flash_key, verify_sbv2
from tests.conftest import require_module
from tests.fixtures.nvs_cases import ROWS, SIZE
from tools.corpus.nvs_writer import build_nvs, encrypt_nvs, nvs_keys_image, to_csv

require_module("espsecure")

RNG = random.Random(7)


def run(*args: str, cwd: Path) -> None:
    proc = subprocess.run(
        [sys.executable, *args], capture_output=True, text=True, check=False, cwd=cwd, timeout=300
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.parametrize(
    ("scheme", "keylen"), [("aes-xts", 32), ("aes-xts", 64), ("aes-xts", 16), ("esp32", 32)]
)
def test_flash_crypt_matches_espsecure(scheme: str, keylen: int, tmp_path: Path) -> None:
    key = RNG.randbytes(keylen)
    plain = RNG.randbytes(0x2000)
    (tmp_path / "k.bin").write_bytes(key)
    (tmp_path / "p.bin").write_bytes(plain)
    extra = ["--aes-xts"] if scheme == "aes-xts" else ["--flash-crypt-conf", "0xF"]
    run(
        "-m",
        "espsecure",
        "encrypt-flash-data",
        "--keyfile",
        "k.bin",
        "--output",
        "c.bin",
        "--address",
        "0x10000",
        *extra,
        "p.bin",
        cwd=tmp_path,
    )
    official = (tmp_path / "c.bin").read_bytes()
    k = load_flash_key(key, scheme)  # type: ignore[arg-type]
    assert flash_crypt(plain, 0x10000, k, scheme, decrypt=False) == official  # type: ignore[arg-type]
    assert flash_crypt(official, 0x10000, k, scheme) == plain  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", ["rsa", "ecdsa256"])
def test_sbv2_verifies_espsecure_signatures(kind: str, tmp_path: Path) -> None:
    priv = (
        rsa.generate_private_key(65537, 3072)
        if kind == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    (tmp_path / "key.pem").write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (tmp_path / "img.bin").write_bytes(RNG.randbytes(6000))
    run(
        "-m",
        "espsecure",
        "sign-data",
        "--version",
        "2",
        "--keyfile",
        "key.pem",
        "--output",
        "signed.bin",
        "img.bin",
        cwd=tmp_path,
    )
    signed = (tmp_path / "signed.bin").read_bytes()
    [res] = verify_sbv2(signed, priv.public_key())
    assert res.verified, res.reason
    other = (
        rsa.generate_private_key(65537, 3072)
        if kind == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    assert not verify_sbv2(signed, other.public_key())[0].verified


def test_nvs_encryption_matches_official_tool(tmp_path: Path) -> None:
    require_module("esp_idf_nvs_partition_gen")
    key = RNG.randbytes(64)
    (tmp_path / "keys.bin").write_bytes(nvs_keys_image(key))
    (tmp_path / "in.csv").write_text(to_csv(ROWS))
    run(
        "-m",
        "esp_idf_nvs_partition_gen",
        "encrypt",
        "in.csv",
        "enc.bin",
        hex(SIZE),
        "--inputkey",
        "keys.bin",
        cwd=tmp_path,
    )
    official = (tmp_path / "enc.bin").read_bytes()
    plain = build_nvs(ROWS, SIZE)
    assert encrypt_nvs(plain, key) == official
    assert decrypt_nvs(official, key) == plain
