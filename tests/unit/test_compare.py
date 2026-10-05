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


def test_claimed_rule_that_ends_in_error_or_notchecked_is_claimed_failing(before: bytes, after: bytes):
    controls, exceptions = load_controls(F / "controls.yml"), load_exceptions(F / "group_vars.yml")
    b = parse_results(before, PROFILE)
    for bad in ("error", "notchecked", "unknown"):
        broken = after.replace(
            b'content_rule_sysctl_net_ipv4_ip_forward"><result>pass</result>',
            f'content_rule_sysctl_net_ipv4_ip_forward"><result>{bad}</result>'.encode(),
        )
        c = compare(b, parse_results(broken, PROFILE, max_unchecked=1.0), controls, exceptions)
        assert full_id("sysctl_net_ipv4_ip_forward") in c.claimed_failing, bad


def test_pass_to_notchecked_is_a_regression(before: bytes, after: bytes):
    controls, exceptions = load_controls(F / "controls.yml"), load_exceptions(F / "group_vars.yml")
    before_ok = before.replace(
        b'content_rule_partition_for_tmp"><result>fail</result>',
        b'content_rule_partition_for_tmp"><result>pass</result>',
    )
    broken = after.replace(
        b'content_rule_partition_for_tmp"><result>fail</result>',
        b'content_rule_partition_for_tmp"><result>notchecked</result>',
    )
    c = compare(
        parse_results(before_ok, PROFILE), parse_results(broken, PROFILE, max_unchecked=1.0), controls, exceptions
    )
    assert full_id("partition_for_tmp") in c.regressions
