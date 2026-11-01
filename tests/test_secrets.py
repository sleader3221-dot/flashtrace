from flashtrace.secrets import (
    find_aws_keys,
    find_certificates,
    find_credentials,
    find_generic_tokens,
    find_mqtt,
    find_private_keys,
    find_urls,
    looks_like_secret_value,
)
from tests.fixtures.crypto_material import der_cert, pem_cert, pem_private_key

AWS = b"AKIAIOSFODNN7EXAMPLE"
TOKEN = b"tok_EXAMPLE_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z"


def kinds(it: object) -> list[str]:
    return [m.kind for m in it]  # type: ignore[attr-defined]


def test_private_key() -> None:
    pem = pem_private_key()
    ms = list(find_private_keys(b"\x00junk" + pem + b"\x00"))
    assert len(ms) == 1 and ms[0].rel == 5 and ms[0].value == pem.strip()
    assert (
        list(find_private_keys(b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")) == []
    )


def test_certificates_pem_and_der() -> None:
    blob = b"xx" + pem_cert() + b"\x00" * 7 + der_cert() + b"\x00"
    ms = list(find_certificates(blob))
    assert kinds(ms) == ["pem_cert", "der_cert"]
    assert all("flashtrace-test.invalid" in m.context for m in ms)
    assert ms[1].value == der_cert()
    # a SEQUENCE header that does not parse is not a certificate
    assert list(find_certificates(b"\x30\x82\x00\x50\x30\x82" + b"\x00" * 80)) == []


def test_aws_and_generic_tokens() -> None:
    data = b"key=" + AWS + b";other=" + TOKEN + b"\x00"
    assert [m.value for m in find_aws_keys(data)] == [AWS]
    assert [m.value for m in find_generic_tokens(data)] == [TOKEN]
    negatives = [
        b"a" * 40,  # no entropy
        b"0123456789abcdef" * 4,  # hex digest
        b"ThisIsJustAVeryLongCamelCaseIdentifierName",  # no digits
        b"AKIAIOSFODNN7EXAMPL",  # 19 chars
    ]
    for n in negatives:
        assert list(find_generic_tokens(n)) == [] and list(find_aws_keys(n)) == []


def test_mqtt_and_urls() -> None:
    data = b"mqtts://broker.example.com:8883/dev\x00tcp host iot.example.net:1883\x00x:1883"
    assert [m.value for m in find_mqtt(data)] == [
        b"mqtts://broker.example.com:8883/dev",
        b"iot.example.net:1883",
    ]
    assert [m.value for m in find_urls(b"see https://ota.example.com/fw.bin.")] == [
        b"https://ota.example.com/fw.bin"
    ]
    assert list(find_mqtt(b"port 1883 and 8883")) == [] and list(find_urls(b"http:/x")) == []


def test_credentials() -> None:
    data = b'{"password": "S3cr3t-Value"} wifi_pwd=letmein123 https://admin:hunter22@x.example/'
    got = [(m.kind, m.value, m.context) for m in find_credentials(data)]
    assert ("credential_assignment", b"S3cr3t-Value", "password") in got
    assert ("url_userinfo", b"hunter22", "user=admin") in got
    for neg in (b"password=%s", b"password: changeme", b"password=", b"passwords are great"):
        assert list(find_credentials(neg)) == [], neg


def test_looks_like_secret_value() -> None:
    assert looks_like_secret_value(TOKEN) == "generic_token"
    assert looks_like_secret_value(AWS) == "aws_key_id"
    assert looks_like_secret_value(b"sensor-01") is None
