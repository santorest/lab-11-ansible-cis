"""Controls the roles claim (policy/controls.yml), documented exceptions (group_vars) and the gate policy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

PREFIX = "xccdf_org.ssgproject.content_rule_"


class ConfigError(ValueError):
    """A configuration file is missing, malformed or inconsistent with the scan."""


@dataclass(frozen=True)
class Control:
    cis: str
    title: str
    role: str
    rules: tuple[str, ...]


@dataclass(frozen=True)
class CisException:
    cis: str
    rules: tuple[str, ...]
    reason: str
    owner_role: str


@dataclass(frozen=True)
class Policy:
    threshold: float
    profile: str
    datastream: str
    ssg_version: str


def full_id(short: str) -> str:
    return short if short.startswith(PREFIX) else PREFIX + short


def _yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping")
    return data


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def load_controls(path: Path) -> list[Control]:
    try:
        return [
            Control(str(c["cis"]), str(c["title"]), str(c["role"]), tuple(str(r) for r in c["rules"]))
            for c in _yaml(path)["controls"]
        ]
    except (KeyError, TypeError) as exc:
        raise ConfigError(f"{path}: malformed control ({exc})") from exc


def load_exceptions(path: Path) -> list[CisException]:
    try:
        return [
            CisException(
                str(e["cis"]), tuple(str(r) for r in e["rules"]), _text(e.get("reason")), _text(e.get("owner_role"))
            )
            for e in _yaml(path).get("cis_exceptions") or []
        ]
    except (KeyError, TypeError) as exc:
        raise ConfigError(f"{path}: malformed exception ({exc})") from exc


def load_policy(path: Path) -> Policy:
    data = _yaml(path)
    try:
        threshold = float(data["gate"]["min_score_excluding_exceptions"])
        ssg = data["ssg"]
        return Policy(threshold, str(ssg["profile"]), str(ssg["datastream"]), str(ssg["version"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: malformed policy ({exc})") from exc


def check_consistency(controls: list[Control], exceptions: list[CisException], profile_rules: set[str]) -> None:
    claimed = {full_id(r) for c in controls for r in c.rules}
    for e in exceptions:
        if not e.reason or not e.owner_role:
            raise ConfigError(f"exception {e.cis}: a reason and an owner role are required")
        for r in e.rules:
            if full_id(r) in claimed:
                raise ConfigError(f"exception {e.cis}: rule {r} is also claimed as remediated")
    named = [(f"control {c.cis}", c.rules) for c in controls] + [(f"exception {e.cis}", e.rules) for e in exceptions]
    for name, rules in named:
        for r in rules:
            if full_id(r) not in profile_rules:
                raise ConfigError(f"{name}: rule {r} is not in the scanned profile")
