from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from cisreport.config import (
    CisException,
    ConfigError,
    Control,
    check_consistency,
    full_id,
    load_controls,
    load_exceptions,
    load_policy,
)

F = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[2]
SHORT = ("sshd_disable_root_login", "sysctl_net_ipv4_ip_forward", "banner_etc_issue", "partition_for_tmp",
         "package_telnet_removed")  # fmt: skip
PROFILE_RULES = {full_id(r) for r in SHORT}


def test_load_and_check():
    controls, exceptions = load_controls(F / "controls.yml"), load_exceptions(F / "group_vars.yml")
    assert [c.cis for c in controls] == ["5.1.20", "3.3.1", "1.6.2"] and exceptions[0].rules == ("partition_for_tmp",)
    check_consistency(controls, exceptions, PROFILE_RULES)


def test_repository_policy_loads():
    p = load_policy(ROOT / "policy" / "policy.yml")
    assert p.threshold == 90.0 and p.profile.endswith("cis_level1_server") and p.ssg_version == "0.1.82"


def test_exception_without_reason_is_an_error():
    controls, exceptions = load_controls(F / "controls.yml"), load_exceptions(F / "group_vars.yml")
    with pytest.raises(ConfigError, match="reason"):
        check_consistency(controls, [replace(exceptions[0], reason="")], PROFILE_RULES)


def test_exception_for_a_claimed_rule_is_an_error():
    controls, exceptions = load_controls(F / "controls.yml"), load_exceptions(F / "group_vars.yml")
    extra = CisException("5.1.20", ("sshd_disable_root_login",), "r", "o")
    with pytest.raises(ConfigError, match="also claimed"):
        check_consistency(controls, [*exceptions, extra], PROFILE_RULES)


def test_rule_not_in_the_profile_is_an_error():
    controls, exceptions = load_controls(F / "controls.yml"), load_exceptions(F / "group_vars.yml")
    extra = Control("9.9", "t", "cis_x", ("does_not_exist",))
    with pytest.raises(ConfigError, match="not in the scanned profile"):
        check_consistency([*controls, extra], exceptions, PROFILE_RULES)


def test_malformed_files_are_config_errors(tmp_path: Path):
    bad = tmp_path / "c.yml"
    bad.write_text("controls:\n  - {cis: '1'}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="malformed"):
        load_controls(bad)
    with pytest.raises(ConfigError, match="cannot read"):
        load_exceptions(tmp_path / "missing.yml")
