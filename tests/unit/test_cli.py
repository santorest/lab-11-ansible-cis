from __future__ import annotations

from pathlib import Path

import pytest

from cisreport import cli

F = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[2]
CLEAN = "PLAY RECAP ***\nlocalhost : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n"


def run_report(tmp_path: Path, after: str = "after.xml", second: str = CLEAN) -> int:
    (tmp_path / "second.log").write_text(second)
    return cli.main(
        ["report", "--policy", str(ROOT / "policy" / "policy.yml"), "--controls", str(F / "controls.yml"),
         "--group-vars", str(F / "group_vars.yml"), "--before", str(F / "before.xml"), "--after", str(F / after),
         "--second-run", str(tmp_path / "second.log"), "--out-dir", str(tmp_path / "out"), "--meta", "run=local"]
    )  # fmt: skip


def test_report_then_gate_fails_on_the_fixture(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert run_report(tmp_path) == 0
    assert {p.name for p in (tmp_path / "out").iterdir()} == {"results.json", "summary.md", "report.html"}
    assert cli.main(["gate", "--results", str(tmp_path / "out" / "results.json")]) == 1
    assert "regression" in capsys.readouterr().out


def test_missing_recap_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert run_report(tmp_path, second="no recap here") == 2
    assert "PLAY RECAP" in capsys.readouterr().err


def test_missing_scan_exits_2(tmp_path: Path):
    assert run_report(tmp_path, after="missing.xml") == 2


def test_gate_passes_on_clean_results(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    results = tmp_path / "r.json"
    results.write_text(
        '{"scores": {"after_excl": 95.0}, "threshold": 90.0, "claimed_failing": [], "regressions": [],'
        ' "idempotent": true, "second_run": []}'
    )
    assert cli.main(["gate", "--results", str(results)]) == 0
    assert "gate passed" in capsys.readouterr().out


def test_controls_markdown(tmp_path: Path):
    out = tmp_path / "controls.md"
    args = ["controls-md", "--controls", str(F / "controls.yml"), "--group-vars", str(F / "group_vars.yml"),
            "--out", str(out)]  # fmt: skip
    assert cli.main(args) == 0
    text = out.read_text(encoding="utf-8")
    assert "| 5.1.20 |" in text and "cis_access" in text and "a booted CI runner cannot be repartitioned" in text
