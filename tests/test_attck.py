from __future__ import annotations

from flashtrace.attck import TECHNIQUE_RE, enrich, load_map
from flashtrace.diff import DIFF_RULES
from flashtrace.model import make_evidence, make_finding
from flashtrace.rules import load_rules


def test_every_rule_id_is_mapped() -> None:
    m = load_map()
    rule_ids = set(load_rules()) | set(DIFF_RULES)
    assert rule_ids <= set(m), sorted(rule_ids - set(m))
    assert set(m) <= rule_ids, sorted(set(m) - rule_ids)


def test_mapping_hygiene() -> None:
    for rid, mp in load_map().items():
        assert mp.technique is None or TECHNIQUE_RE.match(mp.technique), rid
        if mp.technique is None:
            assert mp.review, f"{rid}: null technique must be marked review: true"


def test_only_confirmed_mappings_are_attached() -> None:
    ev = (make_evidence(b"abcd", 0, 4, None),)
    f1 = make_finding(
        "SEC.HARDCODED_CREDENTIAL", severity="high", title="t", detail={}, evidence=ev
    )
    f2 = make_finding("SEC.API_KEY", severity="high", title="t", detail={}, evidence=ev)
    a, b = enrich([f1, f2])
    assert a.attck == ("T0891",) and a.id == f1.id
    assert b.attck == ()  # proposed only (review: true)
