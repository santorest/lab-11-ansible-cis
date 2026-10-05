from __future__ import annotations

import pytest

from cisreport.xccdf import ScanError, parse_results
from tests.unit.conftest import PROFILE

R = "xccdf_org.ssgproject.content_rule_"


def test_selected_rules_with_titles(before: bytes):
    results = parse_results(before, PROFILE)
    assert len(results) == 5 and R + "not_in_profile" not in results
    root = results[R + "sshd_disable_root_login"]
    assert (root.result, root.title, root.severity) == ("fail", "Disable SSH Root Login", "medium")
    assert results[R + "package_telnet_removed"].result == "notapplicable"


def test_empty_result_set_is_an_error(before: bytes):
    only_unselected = before
    for res in (b"fail", b"pass", b"notapplicable"):
        only_unselected = only_unselected.replace(b"<result>" + res + b"</result>", b"<result>notselected</result>")
    with pytest.raises(ScanError, match="no rule was selected"):
        parse_results(only_unselected, PROFILE)


def test_profile_mismatch_is_an_error(before: bytes):
    with pytest.raises(ScanError, match="profile"):
        parse_results(before, "xccdf_org.ssgproject.content_profile_stig")


@pytest.mark.parametrize("xml", [b"", b"not xml", b"<a/>"])
def test_not_a_result_file(xml: bytes):
    with pytest.raises(ScanError):
        parse_results(xml, PROFILE)


def test_scan_with_no_pass_or_fail_is_an_error(before: bytes):
    broken = before
    for res in (b"fail", b"pass"):
        broken = broken.replace(b"<result>" + res + b"</result>", b"<result>error</result>")
    with pytest.raises(ScanError, match="no rule passed or failed"):
        parse_results(broken, PROFILE)


def test_scan_with_too_many_unchecked_rules_is_an_error(after: bytes):
    # one of the five selected rules in error: 20 % of the scan did not really run
    broken = after.replace(
        b'content_rule_sysctl_net_ipv4_ip_forward"><result>pass</result>',
        b'content_rule_sysctl_net_ipv4_ip_forward"><result>error</result>',
    )
    with pytest.raises(ScanError, match="did not evaluate"):
        parse_results(broken, PROFILE)
    assert len(parse_results(broken, PROFILE, max_unchecked=0.25)) == 5
