import json
from pathlib import Path

import pytest

from strix.interface.blue import BlueError, _copy_snapshot, build_manifest
from strix.interface.blue_findings import extract_findings, save_findings
from strix.interface.blue_handoff import load_staged_handoff, stage_handoff
from strix.report.cases import case_timeline, list_case_runs


def test_source_finding_handoff_is_hashed_and_linked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    output = tmp_path / "runs" / "blue-source"
    output.parent.mkdir(parents=True)
    manifest = build_manifest(target, output, "gpt-6-sol", "deny", case_id="case-1")
    output.mkdir()
    _copy_snapshot(manifest)
    manifest["status"] = "completed"
    (output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (output / "report.md").write_text(
        "Observation.\n<strix-findings-json>"
        '[{"id":"F-1","title":"Example issue","description":"Observed in source",'
        '"severity":"low","path":"owned.cs","line":1,"evidence":"line 1",'
        '"remediation":"Review code","uncertainty":"Runtime not tested"}]'
        "</strix-findings-json>", encoding="utf-8",
    )
    assert save_findings(output, manifest) == 1
    stage, record = stage_handoff(
        "blue-source", ["F-1"], ["Can this be reproduced?"],
        "Only the staged copy; no remote endpoints", "openai/local-test", "http://127.0.0.1:11434/v1",
    )
    assert record["case_id"] == "case-1"
    assert record["parent_run_id"] == "blue-source"
    assert (stage / "target" / "owned.cs").read_bytes() == target.read_bytes()
    assert len(record["findings"]) == 1
    assert load_staged_handoff(stage)["finding_refs"] == ["F-1"]
    (stage / "target" / "owned.cs").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(BlueError, match="hashes"):
        load_staged_handoff(stage)
    assert list_case_runs()[0].mode == "blue"
    assert case_timeline("case-1") == []


def test_finding_location_must_match_saved_source(tmp_path: Path) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("line\n", encoding="utf-8")
    manifest = build_manifest(target, tmp_path / "run", "gpt-6-sol", "deny")
    _copy_snapshot(manifest)
    report = (
        '<strix-findings-json>[{"id":"F-1","title":"Issue","description":"Claim",'
        '"severity":"low","path":"owned.cs","line":200}]</strix-findings-json>'
    )
    with pytest.raises(ValueError, match="outside"):
        extract_findings(report, manifest)
