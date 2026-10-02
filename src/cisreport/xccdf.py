"""Read an OpenSCAP ARF/XCCDF results file: the profile's selected rules, their result, title and severity."""

from __future__ import annotations

from dataclasses import dataclass
from xml.etree.ElementTree import ParseError

import defusedxml.ElementTree as ET

NS = "{http://checklists.nist.gov/xccdf/1.2}"
RESULTS = ("pass", "fail", "notapplicable", "notchecked", "error", "unknown", "informational", "fixed")


class ScanError(ValueError):
    """The results file does not describe a real scan of the expected profile."""


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    result: str
    title: str
    severity: str


def parse_results(xml: bytes, profile: str) -> dict[str, RuleResult]:
    try:
        root = ET.fromstring(xml)
    except (ParseError, ValueError) as exc:
        raise ScanError(f"not an XML results file: {exc}") from exc
    tests = list(root.iter(f"{NS}TestResult"))
    if not tests:
        raise ScanError("no XCCDF TestResult in the file")
    test = tests[-1]
    used = test.find(f"{NS}profile")
    used_id = used.get("idref") if used is not None else None
    if used_id != profile:
        raise ScanError(f"results are for profile {used_id}, not {profile}")
    rules = {r.get("id"): r for r in root.iter(f"{NS}Rule")}
    out: dict[str, RuleResult] = {}
    for rr in test.iter(f"{NS}rule-result"):
        result = (rr.findtext(f"{NS}result") or "").strip()
        rule_id = rr.get("idref") or ""
        if result == "notselected" or not rule_id:
            continue
        if result not in RESULTS:
            raise ScanError(f"{rule_id}: unknown result {result!r}")
        rule = rules.get(rule_id)
        title = (rule.findtext(f"{NS}title") or "").strip() if rule is not None else ""
        severity = rule.get("severity", "") if rule is not None else ""
        out[rule_id] = RuleResult(rule_id, result, title, severity or "unknown")
    if not out:
        raise ScanError("no rule was selected: the profile matched nothing")
    return out
