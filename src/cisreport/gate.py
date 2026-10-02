"""Fail on a low score, a claimed control that still fails, a regression, or a non-idempotent second run."""

from __future__ import annotations

from typing import Any

from cisreport.config import PREFIX


def failures(results: dict[str, Any]) -> list[str]:
    out: list[str] = []
    after = results["scores"]["after_excl"]
    if after is None or after < results["threshold"]:
        shown = "none" if after is None else f"{after:.1f} %"
        out.append(f"score excluding exceptions {shown} is below {results['threshold']:g} %")
    for rule in results["claimed_failing"]:
        out.append(f"claimed control still fails: {rule.removeprefix(PREFIX)}")
    for rule in results["regressions"]:
        out.append(f"regression (passed before, fails after): {rule.removeprefix(PREFIX)}")
    if not results["idempotent"]:
        hosts = ", ".join(f"{r['host']} changed={r['changed']} failed={r['failed']}" for r in results["second_run"])
        out.append(f"second run is not idempotent: {hosts}")
    return out
