from __future__ import annotations

from pathlib import Path

from cisreport.compare import compare
from cisreport.config import full_id, load_controls, load_exceptions
from cisreport.score import Counts, count, score
from cisreport.xccdf import parse_results
from tests.unit.conftest import PROFILE

F = Path(__file__).parent / "fixtures"


def test_counts_and_scores(before: bytes, after: bytes):
    b, a = parse_results(before, PROFILE), parse_results(after, PROFILE)
    cb, ca = count(b), count(a)
    assert (cb.passed, cb.failed, cb.notapplicable) == (1, 3, 1) and score(cb) == 25.0
    assert (ca.passed, ca.failed) == (2, 2) and score(ca) == 50.0
    assert score(count(a, {full_id("partition_for_tmp")})) == 2 / 3 * 100


def test_comparison_finds_fixes_regressions_and_claimed_failures(before: bytes, after: bytes):
    controls, exceptions = load_controls(F / "controls.yml"), load_exceptions(F / "group_vars.yml")
    c = compare(parse_results(before, PROFILE), parse_results(after, PROFILE), controls, exceptions)
    assert c.fixed == (full_id("sshd_disable_root_login"), full_id("sysctl_net_ipv4_ip_forward"))
    # passed before, fails after: reported although the score rose
    assert c.regressions == (full_id("banner_etc_issue"),)
    assert c.claimed_failing == (full_id("banner_etc_issue"),)
    assert c.excepted_failing == (full_id("partition_for_tmp"),) and c.open_failing == ()


def test_score_is_none_without_pass_or_fail():
    assert score(Counts(0, 0, 4, 0, 0, 0)) is None
