"""Read the PLAY RECAP of an ansible-playbook run to prove (or disprove) idempotency."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

_LINE = re.compile(
    r"^(?P<host>\S+)\s*:\s*ok=(?P<ok>\d+)\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=(?P<skipped>\d+)\s+rescued=(?P<rescued>\d+)\s+ignored=(?P<ignored>\d+)"
)


class RecapError(ValueError):
    """The playbook output has no usable PLAY RECAP."""


@dataclass(frozen=True)
class HostRecap:
    host: str
    ok: int
    changed: int
    unreachable: int
    failed: int
    skipped: int
    rescued: int
    ignored: int


def parse_recap(text: str) -> list[HostRecap]:
    blocks = text.split("PLAY RECAP")
    if len(blocks) < 2:
        raise RecapError("no PLAY RECAP in the playbook output")
    hosts = []
    for line in blocks[-1].splitlines():
        m = _LINE.match(line.strip())
        if m:
            d = m.groupdict()
            host = d.pop("host")
            hosts.append(HostRecap(host, **{k: int(v) for k, v in d.items()}))
    if not hosts:
        raise RecapError("the PLAY RECAP lists no host")
    return hosts


def idempotent(recaps: Sequence[HostRecap]) -> bool:
    return all(r.changed == 0 and r.failed == 0 and r.unreachable == 0 for r in recaps)
