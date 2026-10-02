"""results.json (for the gate), a Markdown summary and an HTML report. Escaped and deterministic."""

from __future__ import annotations

import html
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict

from cisreport.compare import Comparison
from cisreport.config import PREFIX, CisException, Policy, full_id
from cisreport.recap import HostRecap, idempotent
from cisreport.score import score
from cisreport.xccdf import RuleResult


def short(rule: str) -> str:
    return rule.removeprefix(PREFIX)


def md(text: object) -> str:
    return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.1f} %"


def _excepted(comparison: Comparison, exceptions: Sequence[CisException]) -> list[dict[str, str]]:
    by_rule = {full_id(r): e for e in exceptions for r in e.rules}
    return [{"rule": r, "cis": by_rule[r].cis, "reason": by_rule[r].reason} for r in comparison.excepted_failing]


def _title(after: Mapping[str, RuleResult], rule: str) -> str:
    return after[rule].title if rule in after else ""


def results_json(
    comparison: Comparison,
    after: Mapping[str, RuleResult],
    exceptions: Sequence[CisException],
    recaps_second: Sequence[HostRecap],
    policy: Policy,
    meta: dict[str, str],
) -> str:
    c = comparison
    counts = {"before": c.before, "after": c.after, "before_excl": c.before_excl, "after_excl": c.after_excl}
    data = {
        "meta": meta,
        "threshold": policy.threshold,
        "scores": {k: score(v) for k, v in counts.items()},
        "counts": {k: asdict(v) for k, v in counts.items()},
        "fixed": list(c.fixed),
        "regressions": list(c.regressions),
        "claimed_failing": list(c.claimed_failing),
        "excepted_failing": _excepted(c, exceptions),
        "open_failing": list(c.open_failing),
        "second_run": [asdict(r) for r in recaps_second],
        "idempotent": idempotent(recaps_second),
        "titles": {r: _title(after, r) for r in sorted(set(c.still_failing) | set(c.regressions))},
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def render_markdown(
    comparison: Comparison,
    after: Mapping[str, RuleResult],
    exceptions: Sequence[CisException],
    recaps_second: Sequence[HostRecap],
    policy: Policy,
    meta: dict[str, str],
) -> str:
    c = comparison
    out = [
        "## CIS Level 1 hardening",
        "",
        " · ".join(f"{k} {md(v)}" for k, v in sorted(meta.items())),
        "",
        "| | Before | After |",
        "|---|---|---|",
        f"| Score (all rules) | {_pct(score(c.before))} | {_pct(score(c.after))} |",
        f"| Score (excluding exceptions) | {_pct(score(c.before_excl))} | {_pct(score(c.after_excl))} |",
        f"| Pass / fail | {c.before.passed} / {c.before.failed} | {c.after.passed} / {c.after.failed} |",
        f"| Not applicable / not checked | {c.before.notapplicable} / {c.before.notchecked} | "
        f"{c.after.notapplicable} / {c.after.notchecked} |",
        "",
        f"Fixed {len(c.fixed)} · regressions {len(c.regressions)} · still failing {len(c.still_failing)} "
        f"(exceptions {len(c.excepted_failing)}, claimed {len(c.claimed_failing)}, open {len(c.open_failing)}) · "
        f"second run idempotent: {'yes' if idempotent(recaps_second) else 'NO'} · "
        f"gate threshold {policy.threshold:g} %",
        "",
    ]
    sections = (
        ("Regressions", c.regressions),
        ("Claimed but failing", c.claimed_failing),
        ("Open (not mapped, not excepted)", c.open_failing),
    )
    for heading, rules in sections:
        if rules:
            out += [f"### {heading}", "", "| Rule | Title |", "|---|---|"]
            out += [f"| {md(short(r))} | {md(_title(after, r))} |" for r in rules] + [""]
    if c.excepted_failing:
        out += ["### Documented exceptions", "", "| Rule | CIS | Reason |", "|---|---|---|"]
        out += [f"| {md(short(e['rule']))} | {md(e['cis'])} | {md(e['reason'])} |" for e in _excepted(c, exceptions)]
    return "\n".join(out) + "\n"


def render_html(
    comparison: Comparison,
    after: Mapping[str, RuleResult],
    exceptions: Sequence[CisException],
    recaps_second: Sequence[HostRecap],
    policy: Policy,
    meta: dict[str, str],
) -> str:
    e = html.escape
    c = comparison

    def table(rules: Sequence[str]) -> str:
        rows = "".join(f"<tr><td>{e(short(r))}</td><td>{e(_title(after, r))}</td></tr>" for r in rules)
        return f"<table><tr><th>Rule</th><th>Title</th></tr>{rows}</table>"

    excepted = "".join(
        f"<tr><td>{e(short(x['rule']))}</td><td>{e(x['cis'])}</td><td>{e(x['reason'])}</td></tr>"
        for x in _excepted(c, exceptions)
    )
    meta_line = " · ".join(f"{e(k)} {e(v)}" for k, v in sorted(meta.items()))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>CIS hardening</title>'
        "<style>body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;margin:1rem 0}"
        "td,th{border:1px solid #999;padding:.3rem .6rem;text-align:left}</style></head><body>"
        f"<h1>CIS Level 1 hardening</h1><p>{meta_line}</p>"
        "<table><tr><th></th><th>Before</th><th>After</th></tr>"
        f"<tr><td>Score (all rules)</td><td>{_pct(score(c.before))}</td><td>{_pct(score(c.after))}</td></tr>"
        f"<tr><td>Score (excluding exceptions)</td><td>{_pct(score(c.before_excl))}</td>"
        f"<td>{_pct(score(c.after_excl))}</td></tr>"
        f"<tr><td>Pass / fail</td><td>{c.before.passed} / {c.before.failed}</td>"
        f"<td>{c.after.passed} / {c.after.failed}</td></tr></table>"
        f"<h2>Regressions</h2>{table(c.regressions)}<h2>Claimed but failing</h2>{table(c.claimed_failing)}"
        f"<h2>Open</h2>{table(c.open_failing)}"
        f"<h2>Documented exceptions</h2><table><tr><th>Rule</th><th>CIS</th><th>Reason</th></tr>{excepted}</table>"
        f"<p>Second run idempotent: {'yes' if idempotent(recaps_second) else 'NO'} · "
        f"gate threshold {policy.threshold:g} %</p></body></html>\n"
    )
