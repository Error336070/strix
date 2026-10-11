import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from strix.interface.blue import BlueError, _copy_snapshot, build_manifest
from strix.interface.blue_findings import extract_findings, save_findings
from strix.interface.blue_handoff import (
    _standard_command,
    load_staged_handoff,
    preview_handoff,
    run_handoff,
    stage_handoff,
)
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
    preview = preview_handoff(
        "blue-source", ["F-1"], ["Can this be reproduced?"],
        "Only the staged copy; no remote endpoints", "openai/local-test", "http://127.0.0.1:11434/v1",
    )
    assert not (tmp_path / "runs" / "handoffs").exists()
    stage, record = stage_handoff(
        "blue-source", ["F-1"], ["Can this be reproduced?"],
        "Only the staged copy; no remote endpoints", "openai/local-test", "http://127.0.0.1:11434/v1",
        expected_preview_digest=str(preview["preview_sha256"]),
    )
    assert record["preview_sha256"] == preview["preview_sha256"]
    assert record["case_id"] == "case-1"
    assert record["parent_run_id"] == list_case_runs()[0].selector
    assert record["parent_run_name"] == "blue-source"
    assert (stage / "target" / "owned.cs").read_bytes() == target.read_bytes()
    assert len(record["findings"]) == 1
    assert load_staged_handoff(stage)["finding_refs"] == ["F-1"]
    record_path = stage / "handoff.json"
    changed_record = json.loads(record_path.read_text(encoding="utf-8"))
    changed_record["findings"][0]["title"] = "Changed after review"
    record_path.write_text(json.dumps(changed_record), encoding="utf-8")
    with pytest.raises(BlueError, match="differs from the linked Blue evidence"):
        load_staged_handoff(stage)
    record_path.write_text(json.dumps(record), encoding="utf-8")
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


def test_handoff_launch_rechecks_staged_copy_after_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    source = tmp_path / "owned.cs"
    source.write_text("class Owned {}\n", encoding="utf-8")
    blue_run = tmp_path / "runs" / "blue-source"
    blue_run.parent.mkdir(parents=True)
    manifest = build_manifest(source, blue_run, "gpt-6-sol", "deny", case_id="case-1")
    blue_run.mkdir()
    _copy_snapshot(manifest)
    manifest["status"] = "completed"
    (blue_run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (blue_run / "vulnerabilities.json").write_text(
        json.dumps([{"id": "F-1", "title": "Owned fixture", "path": "owned.cs"}]),
        encoding="utf-8",
    )
    preview = preview_handoff("blue-source", ["F-1"], [], "Staged copy only", None, None)
    findings_path = blue_run / "vulnerabilities.json"
    findings_original = findings_path.read_text(encoding="utf-8")
    findings_path.write_text(
        json.dumps([{"id": "F-1", "title": "Changed", "path": "owned.cs"}]),
        encoding="utf-8",
    )
    with pytest.raises(BlueError, match="changed after preview"):
        stage_handoff(
            "blue-source", ["F-1"], [], "Staged copy only", None, None,
            expected_preview_digest=str(preview["preview_sha256"]),
        )
    assert not (tmp_path / "runs" / "handoffs").exists()
    findings_path.write_text(findings_original, encoding="utf-8")
    stage, _ = stage_handoff("blue-source", ["F-1"], [], "Staged copy only", None, None)

    command, environment = _standard_command(
        stage, "openai/local-test", "http://127.0.0.1:11434/v1",
        hashlib.sha256((stage / "handoff.json").read_bytes()).hexdigest(),
    )
    assert command[1:3] == ["-P", "-c"]
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "strix.py").write_text("raise RuntimeError('shadowed')", encoding="utf-8")
    imported = subprocess.run(  # noqa: S603 - fixed import-only smoke script
        [*command[:3], "from strix.interface.main import main; print(main.__module__)"],
        cwd=shadow, env=environment, check=True, capture_output=True, text=True,
    )
    assert imported.stdout.strip() == "strix.interface.main"

    def tamper_at_prompt(_prompt: str) -> str:
        (stage / "target" / "owned.cs").write_text("changed\n", encoding="utf-8")
        digest = hashlib.sha256((stage / "handoff.json").read_bytes()).hexdigest()
        return "STANDARD " + digest[:8]

    monkeypatch.setattr("builtins.input", tamper_at_prompt)
    monkeypatch.setattr(
        "strix.interface.blue_handoff.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("Changed target must not reach Standard"),
    )
    args = SimpleNamespace(
        staged=stage, launch=True, run=None, finding=[], scope=None, question=[],
        model="openai/local-test", endpoint="http://127.0.0.1:11434/v1",
    )
    with pytest.raises(BlueError, match="hashes"):
        run_handoff(args)
