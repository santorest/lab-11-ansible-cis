from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cisreport.compare import compare
from cisreport.config import load_controls, load_exceptions, load_policy
from cisreport.gate import failures
from cisreport.recap import parse_recap
from cisreport.report import render_html, render_markdown, results_json
from cisreport.xccdf import parse_results
from tests.unit.conftest import PROFILE

F = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[2]
CLEAN = "PLAY RECAP ***\nlocalhost : ok=180 changed=0 unreachable=0 failed=0 skipped=12 rescued=0 ignored=0\n"


def build(before: bytes, after: bytes, recap: str = CLEAN) -> tuple[tuple[Any, ...], dict[str, Any]]:
    b, a = parse_results(before, PROFILE), parse_results(after, PROFILE)
    controls, exceptions = load_controls(F / "controls.yml"), load_exceptions(F / "group_vars.yml")
    c = compare(b, a, controls, exceptions)
    args = (c, a, exceptions, parse_recap(recap), load_policy(ROOT / "policy" / "policy.yml"), {"run": "local"})
    return args, json.loads(results_json(*args))


def test_fixture_run_fails_on_regression_claimed_rule_and_threshold(before: bytes, after: bytes):
    _, data = build(before, after)
    msgs = failures(data)
    assert any("regression" in m and "banner_etc_issue" in m for m in msgs)
    assert any("claimed" in m and "banner_etc_issue" in m for m in msgs)
    assert any("score" in m and "below 90" in m for m in msgs)
    assert data["excepted_failing"][0]["reason"] == "a booted CI runner cannot be repartitioned"


def test_a_clean_after_scan_passes(before: bytes, after: bytes):
    clean = after.replace(
        b'content_rule_banner_etc_issue"><result>fail</result>', b'content_rule_banner_etc_issue"><result>pass</result>'
    )
    _, data = build(before, clean)
    assert failures(data) == [] and data["scores"]["after_excl"] == 100.0 and data["idempotent"] is True


def test_second_run_with_changes_fails(before: bytes, after: bytes):
    _, data = build(before, after, CLEAN.replace("changed=0", "changed=2"))
    assert any("not idempotent" in m for m in failures(data))


def test_reports_escape_titles(before: bytes, after: bytes):
    args, _ = build(before, after)
    html, md = render_html(*args), render_markdown(*args)
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "\\| pipe" in md


def test_threshold_edges(before: bytes, after: bytes):
    _, data = build(before, after)
    data |= {"claimed_failing": [], "regressions": [], "idempotent": True, "threshold": 90.0}
    assert failures(data | {"scores": {"after_excl": 90.0}}) == []
    assert any("below 90" in m for m in failures(data | {"scores": {"after_excl": 89.99}}))
    assert any("none" in m for m in failures(data | {"scores": {"after_excl": None}}))


def test_html_report_shows_unchecked_counts(before: bytes, after: bytes):
    args, _ = build(before, after)
    assert "Not applicable / not checked / error" in render_html(*args)
