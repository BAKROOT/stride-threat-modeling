"""Tests for tools/validate_threats.py. Run: python3 -m pytest tools/tests -q"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import validate_threats as vt  # noqa: E402

TODAY = "2026-10-19"

BASE = {
    "model": {"id": "TM-T01", "name": "Test", "owner": "team", "last_reviewed": TODAY},
    "elements": [
        {"id": "E1", "name": "User", "type": "external_entity"},
        {"id": "P1", "name": "API", "type": "process"},
        {"id": "DS1", "name": "DB", "type": "data_store"},
        {"id": "F1", "name": "Request", "type": "data_flow", "from": "E1", "to": "P1"},
    ],
    "threats": [
        {
            "id": "T-01", "title": "IDOR", "elements": ["P1", "DS1"], "stride": ["I", "E"],
            "description": "User reads another user's records", "likelihood": 4, "impact": 4,
            "risk": 16, "band": "High", "response": "mitigate",
            "status": "mitigation-in-progress", "owner": "team",
            "mitigations": [{"id": "M-01a", "description": "Object-level authZ",
                             "verification": "Cross-user test"}],
        }
    ],
}


def run(tmp_path: Path, data: dict, *extra: str) -> int:
    f = tmp_path / "threats.yaml"
    f.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return vt.main([str(f), "--today", TODAY, *extra])


def mutate(fn):
    d = copy.deepcopy(BASE)
    fn(d)
    return d


def test_valid_model_passes(tmp_path):
    assert run(tmp_path, BASE) == 0


def test_orbitpay_example_passes():
    assert vt.main([str(ROOT / "examples/orbitpay/threats.yaml"), "--today", TODAY]) == 0


def test_template_passes():
    assert vt.main([str(ROOT / "templates/threats.yaml"), "--today", TODAY]) == 0


@pytest.mark.parametrize("change, message", [
    (lambda d: d["threats"][0].update(risk=12), "risk 12 != likelihood"),
    (lambda d: d["threats"][0].update(band="Medium"), "should be 'High'"),
    (lambda d: d["threats"][0].update(status="open"), "need a mitigation in progress"),
    (lambda d: d["threats"][0].update(elements=["P9"]), "unknown element P9"),
    (lambda d: d["threats"][0].update(stride=["X"]), "schema"),
    (lambda d: d["threats"][0].update(mitigations=[]), "no mitigations listed"),
    (lambda d: d["threats"].append(copy.deepcopy(d["threats"][0])), "duplicate threat ID"),
    (lambda d: d["elements"][3].update(to="P7"), "unknown element P7"),
])
def test_policy_violations_fail(tmp_path, capsys, change, message):
    assert run(tmp_path, mutate(change)) == 1
    assert message in capsys.readouterr().out


def test_accepted_requires_acceptance_block(tmp_path, capsys):
    d = mutate(lambda d: d["threats"][0].update(status="accepted", response="accept"))
    assert run(tmp_path, d) == 1
    assert "acceptance block" in capsys.readouterr().out


def test_expired_acceptance_fails(tmp_path, capsys):
    def change(d):
        d["threats"][0].update(status="accepted", response="accept", acceptance={
            "approved_by": "VP Eng", "rationale": "Internal only", "expires": "2026-01-01"})
    assert run(tmp_path, mutate(change)) == 1
    assert "expired" in capsys.readouterr().out


def test_valid_acceptance_passes(tmp_path):
    def change(d):
        d["threats"][0].update(status="accepted", response="accept", acceptance={
            "approved_by": "VP Eng", "rationale": "Internal only", "expires": "2027-04-01"})
    assert run(tmp_path, mutate(change)) == 0


def test_low_risk_open_is_allowed(tmp_path):
    d = mutate(lambda d: d["threats"][0].update(likelihood=2, impact=3, risk=6,
                                                band="Medium", status="open"))
    assert run(tmp_path, d) == 0


def test_stale_review_warns_and_strict_fails(tmp_path):
    d = mutate(lambda d: d["model"].update(last_reviewed="2025-01-01"))
    assert run(tmp_path, d) == 0
    assert run(tmp_path, d, "--strict") == 1


def test_coverage_gaps(tmp_path, capsys):
    assert run(tmp_path, BASE, "--coverage") == 0
    out = capsys.readouterr().out
    assert "| P1 API |" in out and "**?**" in out
    assert run(tmp_path, BASE, "--fail-on-gaps") == 1


def test_band_boundaries():
    assert [vt.band_for(r) for r in (5, 6, 11, 12, 19, 20)] == [
        "Low", "Medium", "Medium", "High", "High", "Critical"]
