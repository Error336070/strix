"""Case history stays usable when Blue and Standard runs overlap."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from pathlib import Path

from strix.core.paths import run_dir_for, runs_base_dir
from strix.report.cases import (
    add_catalog_root,
    case_finding_locations,
    case_timeline,
    list_case_handoffs,
    list_case_runs,
    resolve_case_run,
)


def _write(path: Path, name: str, value: dict[str, object]) -> Path:
    directory = path / name
    directory.mkdir(parents=True)
    (directory / "run.json").write_text(json.dumps(value), encoding="utf-8")
    return directory


def test_configured_runs_root_and_legacy_discovery(tmp_path: Path, monkeypatch) -> None:
    primary = tmp_path / "shared"
    legacy = tmp_path / "older"
    monkeypatch.setenv("STRIX_RUNS_DIR", str(primary))
    assert runs_base_dir() == primary
    assert run_dir_for("new") == primary / "new"
    _write(primary, "blue-1", {"mode": "blue", "case_id": "case-1", "status": "running"})
    _write(legacy, "red-1", {"case_id": "case-1", "status": "running"})
    add_catalog_root(legacy)
    runs = list_case_runs()
    assert {(run.run_id, run.mode, run.status) for run in runs} == {
        ("blue-1", "blue", "running"),
        ("red-1", "standard", "running"),
    }
    assert resolve_case_run("red-1") is not None
    assert resolve_case_run("../red-1") is None


def test_legacy_blue_and_live_case_events(tmp_path: Path) -> None:
    primary = tmp_path / "runs"
    blue = primary / "blue-old"
    blue.mkdir(parents=True)
    (blue / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "strix-blue-local-v1",
                "case_id": "case-2",
                "target": "sample.dll",
                "status": "running",
                "created_utc": "2026-10-11T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    (blue / "codex-events.jsonl").write_text(
        json.dumps(
            {
                "method": "item/started",
                "params": {"item": {"type": "dynamicToolCall"}},
                "emittedAtMs": 1791676801000,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    standard = _write(
        primary,
        "red-new",
        {"case_id": "case-2", "status": "running", "start_time": "2026-10-11T00:00:02+00:00"},
    )
    (standard / "agents.json").write_text("{}", encoding="utf-8")
    runs = list_case_runs(primary)
    assert [run.mode for run in runs] == ["standard", "blue"]
    events = case_timeline("case-2", primary)
    assert any(
        event["run_id"] == "blue-old" and event["kind"] == "item/started"
        for event in events
    )
    assert all(event["run_id"] in {"blue-old", "red-new"} for event in events)


def test_case_handoffs_expose_reviewed_metadata_only(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    stage = root / "handoffs" / "handoff-1"
    stage.mkdir(parents=True)
    (stage / "handoff.json").write_text(
        json.dumps(
            {
                "schema": "strix-reviewed-handoff-v1",
                "case_id": "case-1",
                "parent_run_id": "blue-1",
                "finding_refs": ["F-1"],
                "scope": "Only the staged copy",
                "questions": ["Is this reachable?"],
                "files": [{"path": "sample.cs", "sha256": "a" * 64, "size": 5}],
                "launch_ready": False,
                "created_utc": "2026-10-11T00:00:00+00:00",
                "target": "C:/private/staged/target",
            }
        ),
        encoding="utf-8",
    )
    assert list_case_handoffs("other-case", root) == []
    assert list_case_handoffs("case-1", root) == [
        {
            "id": "handoff-1",
            "parent_run_id": "blue-1",
            "finding_refs": ["F-1"],
            "scope": "Only the staged copy",
            "questions": ["Is this reachable?"],
            "files": [{"path": "sample.cs", "sha256": "a" * 64}],
            "launch_ready": False,
            "created_at": "2026-10-11T00:00:00+00:00",
        }
    ]


def test_case_finding_location_uses_its_blue_manifest_hash(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "blue-1"
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "strix-blue-local-v1",
                "case_id": "case-1",
                "files": [{"path": "sample.cs", "sha256": "b" * 64}],
            }
        ),
        encoding="utf-8",
    )
    run = list_case_runs(tmp_path / "runs")[0]
    assert case_finding_locations(
        run,
        {"code_locations": [{"file": "sample.cs", "start_line": 5}]},
    ) == [{"path": "sample.cs", "line": 5, "sha256": "b" * 64}]
