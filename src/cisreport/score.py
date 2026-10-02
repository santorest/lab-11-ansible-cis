"""Counts by result and the compliance score pass / (pass + fail)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cisreport.xccdf import RuleResult


@dataclass(frozen=True)
class Counts:
    passed: int
    failed: int
    notapplicable: int
    notchecked: int
    error: int
    other: int


def count(results: Mapping[str, RuleResult], exclude: set[str] | None = None) -> Counts:
    tally = {"pass": 0, "fail": 0, "notapplicable": 0, "notchecked": 0, "error": 0, "other": 0}
    for rule_id, r in results.items():
        if exclude and rule_id in exclude:
            continue
        tally[r.result if r.result in tally else "other"] += 1
    return Counts(
        tally["pass"], tally["fail"], tally["notapplicable"], tally["notchecked"], tally["error"], tally["other"]
    )


def score(c: Counts) -> float | None:
    total = c.passed + c.failed
    return None if total == 0 else c.passed / total * 100
