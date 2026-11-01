import hashlib

import pytest

from flashtrace.model import (
    ANOMALY_RULE_ID,
    Anomaly,
    anomaly_finding,
    make_evidence,
    make_finding,
)

DUMP = bytes(range(256)) * 4


def test_evidence_hash_matches_bytes() -> None:
    ev = make_evidence(DUMP, 16, 32, "nvs")
    assert ev == ev.__class__("nvs", 16, 32, hashlib.sha256(DUMP[16:48]).hexdigest())


@pytest.mark.parametrize(
    ("offset", "length", "exp_off", "exp_len"),
    [(-5, 10, 0, 10), (1020, 100, 1020, 4), (5000, 10, 1024, 0), (10, -3, 10, 0)],
)
def test_evidence_is_clamped(offset: int, length: int, exp_off: int, exp_len: int) -> None:
    ev = make_evidence(DUMP, offset, length, None)
    assert (ev.offset, ev.length) == (exp_off, exp_len)
    assert ev.sha256 == hashlib.sha256(DUMP[exp_off : exp_off + exp_len]).hexdigest()


def test_finding_id_is_stable_and_evidence_dependent() -> None:
    ev1 = make_evidence(DUMP, 0, 8, "a")
    ev2 = make_evidence(DUMP, 8, 8, "a")
    f1 = make_finding("X.RULE", severity="low", title="t", detail={}, evidence=(ev1,))
    f1b = make_finding("X.RULE", severity="high", title="other", detail={"k": 1}, evidence=(ev1,))
    f2 = make_finding("X.RULE", severity="low", title="t", detail={}, evidence=(ev2,))
    assert f1.id == f1b.id
    assert f1.id != f2.id
    assert f1.id.startswith("X.RULE:")


def test_finding_requires_evidence_and_sane_confidence() -> None:
    with pytest.raises(ValueError, match="Evidence"):
        make_finding("X", severity="low", title="t", detail={}, evidence=())
    ev = make_evidence(DUMP, 0, 1, None)
    with pytest.raises(ValueError, match="confidence"):
        make_finding("X", severity="low", title="t", detail={}, evidence=(ev,), confidence=1.5)


def test_anomaly_finding() -> None:
    f = anomaly_finding(DUMP, Anomaly("TRUNCATED", "short", 100, 4, {"n": 1}), "ota_0")
    assert f.rule_id == ANOMALY_RULE_ID
    assert f.detail == {"kind": "TRUNCATED", "n": 1}
    assert f.evidence[0].partition == "ota_0"
    assert f.evidence[0].sha256 == hashlib.sha256(DUMP[100:104]).hexdigest()
