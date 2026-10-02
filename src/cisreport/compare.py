"""Before/after: what the roles fixed, what still fails (and why) and what got worse."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from cisreport.config import CisException, Control, full_id
from cisreport.score import Counts, count
from cisreport.xccdf import RuleResult


@dataclass(frozen=True)
class Comparison:
    before: Counts
    after: Counts
    before_excl: Counts
    after_excl: Counts
    fixed: tuple[str, ...]
    still_failing: tuple[str, ...]
    regressions: tuple[str, ...]
    claimed_failing: tuple[str, ...]
    excepted_failing: tuple[str, ...]
    open_failing: tuple[str, ...]


def _result(results: Mapping[str, RuleResult], rule: str) -> str:
    return results[rule].result if rule in results else "missing"


def compare(
    before: Mapping[str, RuleResult],
    after: Mapping[str, RuleResult],
    controls: Sequence[Control],
    exceptions: Sequence[CisException],
) -> Comparison:
    excepted = {full_id(r) for e in exceptions for r in e.rules}
    claimed = {full_id(r) for c in controls for r in c.rules}
    keys = sorted(set(before) | set(after))
    fixed = tuple(k for k in keys if _result(before, k) == "fail" and _result(after, k) == "pass")
    failing = tuple(k for k in keys if _result(after, k) == "fail")
    regressions = tuple(k for k in keys if _result(before, k) == "pass" and _result(after, k) in ("fail", "error"))
    return Comparison(
        before=count(before),
        after=count(after),
        before_excl=count(before, excepted),
        after_excl=count(after, excepted),
        fixed=fixed,
        still_failing=failing,
        regressions=regressions,
        claimed_failing=tuple(k for k in failing if k in claimed),
        excepted_failing=tuple(k for k in failing if k in excepted),
        open_failing=tuple(k for k in failing if k not in claimed and k not in excepted),
    )
