"""Key-assisted decryption and Secure Boot V2 verification.

Every algorithm here follows the official tools line by line; CI checks each one
against those tools (``tests/test_crypto_official.py``):

* Flash encryption (esptool v5.1.0 ``espsecure`` ``_flash_encryption_operation_aes_xts``
  and ``_flash_encryption_operation_esp32``, ``_load_hardware_key``):
  - AES-XTS (ESP32-S2/S3/C3/C6/...): 128-byte blocks, tweak = LE u32 of the block's
    flash address (``addr & ~0x7F``) + 12 zero bytes, input and output byte-reversed.
  - ESP32: AES-256-ECB *encrypt* to decrypt, per 16-byte block byte-reversed, with the
    key "tweaked" per 32-byte flash block from FLASH_CRYPT_CONFIG (default 0xF).
  - Key files of 16 bytes are extended with SHA-256, 24-byte keys with ``key[8:16]``.
* NVS encryption (esp-idf-nvs-partition-gen 0.2.0 ``encrypt_data``/``decrypt_data``):
  each 32-byte entry is AES-XTS with the 64-byte key ``e_key || t_key``; tweak = the
  entry's partition-relative address as a 16-byte little-endian integer. Page headers
  and the entry bitmap are plaintext. The nvs_keys partition holds ``e_key || t_key``
  followed by ``crc32(key, 0xFFFFFFFF)``.
* Secure Boot V2 (espsecure ``verify_signature_v2``, ``validate_signature_block``):
  the signed data is the image padded with 0xFF to a 4 KB boundary; the last 4 KB
  sector holds up to 3 blocks of 1216 bytes (``crc32(block[:1196])`` at 1196).
  RSA-3072 PSS(SHA-256, salt 32) with the signature byte-reversed; ECDSA P-192/P-256
  (SHA-256) or P-384 (SHA-384) with r, s stored little-endian.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from typing import Literal

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import HashAlgorithm

from flashtrace.model import ByteSource

SECTOR = 4096
SIG_BLOCK_LEN = 1216
NVS_PAGE = 4096
NVS_FIRST_ENTRY = 64
NVS_ENTRY = 32
NVS_ENTRIES = 126

Scheme = Literal["aes-xts", "esp32"]

# --- flash encryption --------------------------------------------------------

# Key tweak pattern from espsecure (bit k of the flash offset flips key bit n).
_TWEAK_PATTERN_CHECK = 256


def load_flash_key(raw: bytes, scheme: Scheme) -> bytes:
    """Normalise a flash-encryption key file exactly like espsecure ``_load_hardware_key``."""
    if len(raw) not in (16, 24, 32, 64):
        raise ValueError(f"flash key must be 16, 24, 32 or 64 bytes, got {len(raw)}")
    if scheme == "esp32" and len(raw) not in (24, 32):
        raise ValueError("ESP32 flash encryption supports only 192- and 256-bit keys")
    if scheme == "aes-xts" and len(raw) == 24:
        raise ValueError("AES-XTS supports only 128-, 256- and 512-bit keys")
    if len(raw) == 16:
        return hashlib.sha256(raw).digest()
    if len(raw) == 24:
        return raw + raw[8:16]
    return raw


def _xts_flash(data: bytes, address: int, key: bytes, decrypt: bool) -> bytes:
    if address % 16 or len(data) % 16:
        raise ValueError("address and length must be multiples of 16")
    pad_left = address % 0x80
    buf = b"\x00" * pad_left + data
    pad_right = (-len(buf)) % 0x80
    buf += b"\x00" * pad_right
    addr = address
    out = bytearray()
    for i in range(0, len(buf), 0x80):
        tweak = struct.pack("<I", addr & ~0x7F) + b"\x00" * 12
        addr += 0x80
        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
        ctx = cipher.decryptor() if decrypt else cipher.encryptor()
        out += ctx.update(buf[i : i + 0x80][::-1])[::-1]
    res = bytes(out)
    if pad_right:
        res = res[:-pad_right]
    return res[pad_left:]


def _esp32_tweak_range(flash_crypt_conf: int) -> int:
    r = 0
    if flash_crypt_conf & 1:
        r |= 0xFFFFFFFFFFFFFFFFE00000000000000000000000000000000000000000000000
    if flash_crypt_conf & 2:
        r |= 0x00000000000000001FFFFFFFFFFFFFFFF0000000000000000000000000000000
    if flash_crypt_conf & 4:
        r |= 0x000000000000000000000000000000000FFFFFFFFFFFFFFFE000000000000000
    if flash_crypt_conf & 8:
        r |= 0x0000000000000000000000000000000000000000000000001FFFFFFFFFFFFFFF
    return r


_MUL1 = 0x0000200004000080000004000080001000000200004000080000040000800010
_MUL2 = 0x0000000000000000200000000000000010000000000000002000000000000001
_MUL2_MASK = 0x000000000000007FE00000000000000FF000000000000007E00000000000000F


def _esp32_block_key(key: int, offset: int, tweak_range: int) -> bytes:
    addr = offset >> 5
    k = key ^ (((_MUL1 * addr) | ((_MUL2 * addr) & _MUL2_MASK)) & tweak_range)
    return k.to_bytes(32, "big")


def _esp32_flash(
    data: bytes, address: int, key: bytes, flash_crypt_conf: int, decrypt: bool
) -> bytes:
    if address % 16 or len(data) % 16:
        raise ValueError("address and length must be multiples of 16")
    tweak_range = _esp32_tweak_range(flash_crypt_conf)
    k = int.from_bytes(key, "big")
    out = bytearray()
    ctx = None
    for i in range(0, len(data), 16):
        offs = address + i
        if offs % 32 == 0 or ctx is None:
            cipher = Cipher(algorithms.AES(_esp32_block_key(k, offs, tweak_range)), modes.ECB())  # noqa: S305 - ESP32 hardware scheme is per-block AES
            # flash encryption uses AES inverted: decrypting flash = AES encrypt
            ctx = cipher.encryptor() if decrypt else cipher.decryptor()
        out += ctx.update(data[i : i + 16][::-1])[::-1]
    return bytes(out)


def flash_crypt(
    data: ByteSource,
    address: int,
    key: bytes,
    scheme: Scheme,
    *,
    decrypt: bool = True,
    flash_crypt_conf: int = 0xF,
) -> bytes:
    """Decrypt (or, for test fixtures, encrypt) flash bytes located at ``address``."""
    raw = bytes(data)
    if scheme == "aes-xts":
        return _xts_flash(raw, address, key, decrypt)
    return _esp32_flash(raw, address, key, flash_crypt_conf, decrypt)


# --- NVS encryption ----------------------------------------------------------


def parse_nvs_keys(data: ByteSource) -> bytes | None:
    """Return ``e_key || t_key`` (64 bytes) from a plaintext nvs_keys partition, or None."""
    raw = bytes(data[:68])
    if len(raw) < 68:
        return None
    key, (crc,) = raw[:64], struct.unpack_from("<I", raw, 64)
    if key == b"\xff" * 64 or crc != zlib.crc32(key, 0xFFFFFFFF) & 0xFFFFFFFF:
        return None
    return key


def _nvs_tweak(rel_addr: int) -> bytes:
    return rel_addr.to_bytes(16, "little")


def nvs_crypt_entry(entry: bytes, rel_addr: int, key: bytes, decrypt: bool) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.XTS(_nvs_tweak(rel_addr)))
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(entry)


def decrypt_nvs(data: ByteSource, key: bytes) -> bytes:
    """Decrypt every non-empty entry slot of an encrypted NVS partition (headers stay)."""
    if len(key) != 64:
        raise ValueError("NVS key must be 64 bytes (e_key || t_key)")
    buf = bytearray(bytes(data))
    for p in range(len(buf) // NVS_PAGE):
        page = p * NVS_PAGE
        if buf[page : page + 4] == b"\xff\xff\xff\xff":
            continue  # uninitialised page
        bitmap = buf[page + 32 : page + 64]
        for slot in range(NVS_ENTRIES):
            bit = slot * 2
            if (bitmap[bit // 8] >> (bit % 8)) & 0b11 == 0b11:
                continue  # empty slot was never written, so it was never encrypted
            off = page + NVS_FIRST_ENTRY + slot * NVS_ENTRY
            buf[off : off + NVS_ENTRY] = nvs_crypt_entry(
                bytes(buf[off : off + NVS_ENTRY]), off, key, decrypt=True
            )
    return bytes(buf)


# --- Secure Boot V2 ----------------------------------------------------------


@dataclass(frozen=True)
class SignatureCheck:
    block: int
    offset: int  # absolute offset of the signature block
    scheme: str  # "RSA" | "ECDSA-P192" | "ECDSA-P256" | "ECDSA-P384" | "unknown"
    crc_ok: bool
    digest_ok: bool
    verified: bool  # signature valid AND made by the supplied key
    reason: str


def load_public_key(pem_or_der: bytes) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
    """Accept a public key, or a private key (its public half is used)."""
    for loader in (
        serialization.load_pem_public_key,
        serialization.load_der_public_key,
    ):
        try:
            k = loader(pem_or_der)
        except (ValueError, TypeError):
            continue
        if isinstance(k, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
            return k
    for ploader in (serialization.load_pem_private_key, serialization.load_der_private_key):
        try:
            pk = ploader(pem_or_der, password=None)
        except (ValueError, TypeError):
            continue
        pub = pk.public_key()
        if isinstance(pub, rsa.RSAPublicKey | ec.EllipticCurvePublicKey):
            return pub
    raise ValueError("not an RSA or ECDSA public/private key in PEM or DER form")


def verify_sbv2(
    signed: ByteSource,
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    base_offset: int = 0,
) -> list[SignatureCheck]:
    """Verify every signature block in the final 4 KB sector of ``signed``.

    ``signed`` = image padded to a 4 KB boundary + the signature sector.
    """
    data = bytes(signed)
    if len(data) < 2 * SECTOR or len(data) % SECTOR:
        return []
    content, sector = data[:-SECTOR], data[-SECTOR:]
    out: list[SignatureCheck] = []
    for n in range(3):
        blk = sector[n * SIG_BLOCK_LEN : (n + 1) * SIG_BLOCK_LEN]
        off = base_offset + len(content) + n * SIG_BLOCK_LEN
        if blk[0] != 0xE7 or blk[1] not in (0x02, 0x03):
            continue
        (crc,) = struct.unpack_from("<I", blk, 1196)
        crc_ok = crc == zlib.crc32(blk[:1196]) & 0xFFFFFFFF
        out.append(_check_block(n, off, blk, content, key, crc_ok))
    return out


def _check_block(
    n: int,
    off: int,
    blk: bytes,
    content: bytes,
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey,
    crc_ok: bool,
) -> SignatureCheck:
    version, sha_ver = blk[1], blk[2]
    if version == 0x03 and sha_ver == 0x1:
        stored, digest = blk[4:52], hashlib.sha384(content).digest()
    else:
        stored, digest = blk[4:36], hashlib.sha256(content).digest()
    scheme = "RSA" if version == 0x02 else "ECDSA"
    if not crc_ok:
        return SignatureCheck(n, off, scheme, False, stored == digest, False, "block CRC bad")
    if stored != digest:
        return SignatureCheck(n, off, scheme, True, False, False, "image digest mismatch")
    try:
        if version == 0x02:
            if not isinstance(key, rsa.RSAPublicKey):
                return SignatureCheck(n, off, scheme, True, True, False, "key type mismatch")
            sig = blk[36 + 384 + 4 + 384 + 4 : 36 + 384 + 4 + 384 + 4 + 384]
            key.verify(
                sig[::-1],
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                utils.Prehashed(hashes.SHA256()),
            )
        else:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                return SignatureCheck(n, off, scheme, True, True, False, "key type mismatch")
            h: HashAlgorithm
            if sha_ver == 0x1:
                curve_id, rs, keylen = blk[52], blk[52 + 1 + 96 : 52 + 1 + 192], 48
                h = hashes.SHA384()
            else:
                curve_id, rs, keylen = blk[36], blk[36 + 1 + 64 : 36 + 1 + 128], 0
                keylen = {1: 24, 2: 32}.get(curve_id, 0)
                h = hashes.SHA256()
            if keylen == 0:
                return SignatureCheck(
                    n, off, scheme, True, True, False, f"unknown curve {curve_id}"
                )
            scheme = {24: "ECDSA-P192", 32: "ECDSA-P256", 48: "ECDSA-P384"}[keylen]
            r = int.from_bytes(rs[:keylen], "little")
            s = int.from_bytes(rs[keylen : 2 * keylen], "little")
            key.verify(utils.encode_dss_signature(r, s), digest, ec.ECDSA(utils.Prehashed(h)))
    except exceptions.InvalidSignature:
        return SignatureCheck(n, off, scheme, True, True, False, "not signed by the supplied key")
    except (ValueError, TypeError) as exc:
        return SignatureCheck(n, off, scheme, True, True, False, f"malformed block: {exc}")
    return SignatureCheck(n, off, scheme, True, True, True, "verified")


# --- test/corpus helper (signing mirrors espsecure generate_signature_block_*) ----


def sign_sbv2(
    image: bytes,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    *,
    deterministic: bool = False,
) -> bytes:
    """Return ``image`` padded to 4 KB + a one-block signature sector (espsecure layout).

    ``deterministic`` uses RFC 6979 ECDSA so corpus images are reproducible.
    """
    content = image + b"\xff" * (-len(image) % SECTOR)
    if isinstance(private_key, rsa.RSAPrivateKey):
        digest = hashlib.sha256(content).digest()
        sig = private_key.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            utils.Prehashed(hashes.SHA256()),
        )
        nums = private_key.public_key().public_numbers()
        m = -pow(nums.n, -1, 1 << 32)
        rinv = (1 << (private_key.key_size * 2)) % nums.n
        nb = (private_key.key_size + 7) // 8
        block = struct.pack(
            "<BBxx32s384sI384sI384s",
            0xE7,
            0x02,
            digest,
            nums.n.to_bytes(nb, "big")[::-1],
            nums.e,
            rinv.to_bytes(nb, "big")[::-1],
            m & 0xFFFFFFFF,
            sig[::-1],
        )
    else:
        curve = private_key.curve
        if isinstance(curve, ec.SECP384R1):
            raise ValueError("P-384 signing helper not implemented")
        clen, cid = (24, 1) if isinstance(curve, ec.SECP192R1) else (32, 2)
        digest = hashlib.sha256(content).digest()
        sig = private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=deterministic),
        )
        r, s = utils.decode_dss_signature(sig)
        pn = private_key.public_key().public_numbers()

        def le(a: int) -> bytes:
            return a.to_bytes(clen, "big")[::-1]

        block = struct.pack(
            "<BBBx32sB64s64s1031x",
            0xE7,
            0x03,
            0x0,
            digest,
            cid,
            (le(pn.x) + le(pn.y)).ljust(64, b"\x00"),
            (le(r) + le(s)).ljust(64, b"\x00"),
        )
    block += struct.pack("<I", zlib.crc32(block) & 0xFFFFFFFF) + b"\x00" * 16
    if len(block) != SIG_BLOCK_LEN:
        raise ValueError("internal: bad signature block size")
    return content + block + b"\xff" * (SECTOR - SIG_BLOCK_LEN)
