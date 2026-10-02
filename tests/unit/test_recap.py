from __future__ import annotations

import pytest

from cisreport.recap import RecapError, idempotent, parse_recap

FIRST = """PLAY [harden] ****
TASK [x] ****
changed: [localhost]
PLAY RECAP *********************************************************************
localhost                  : ok=180  changed=96   unreachable=0    failed=0    skipped=12   rescued=0    ignored=0
"""
SECOND = FIRST.replace("changed=96", "changed=0 ")
OTHER = "other : ok=3 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0\n"


def test_parses_counts():
    [r] = parse_recap(FIRST)
    assert (r.host, r.ok, r.changed, r.failed, r.skipped) == ("localhost", 180, 96, 0, 12)
    assert not idempotent([r]) and idempotent(parse_recap(SECOND))


def test_uses_the_last_recap_block():
    assert idempotent(parse_recap(FIRST + "\n" + SECOND))
    assert not idempotent(parse_recap(SECOND + "\n" + FIRST))


def test_any_host_with_changes_or_failures_breaks_idempotency():
    two = SECOND + OTHER
    assert len(parse_recap(two)) == 2 and not idempotent(parse_recap(two))


@pytest.mark.parametrize("text", ["", "PLAY RECAP ****\n", "TASK [x]\nok: [localhost]\n"])
def test_no_recap_is_an_error(text: str):
    with pytest.raises(RecapError):
        parse_recap(text)
