"""Operator-reviewed Blue handoff; launch is mocked and never starts Standard."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest

from strix.interface import blue_handoff
from strix.interface.tui.backend.controller import TuiController


def _args() -> argparse.Namespace:
    return argparse.Namespace(
        needs_setup=True, targets_info=[], instruction=None, scan_mode="deep",
        max_budget_usd=None, max_turns=500, scope_mode="auto", diff_base=None,
    )


async def _completed_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TuiController:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())
    preview = await controller.handle("setup.blue_prepare", {"target": str(target)})
    manifest_path = Path(preview["manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["status"] = "completed"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    findings = [{
        "id": "F-1", "title": "Owned finding", "severity": "medium",
        "evidence": f"owned.cs:1 SHA-256 {digest}", "source_sha256": digest,
    }]
    (manifest_path.parent / "vulnerabilities.json").write_text(
        json.dumps(findings), encoding="utf-8"
    )
    controller.setup_mode = False
    controller.scan_started = True
    controller.scan_state = "completed"
    controller._refresh_blue_findings(manifest_path.parent)
    return controller


@pytest.mark.asyncio
async def test_handoff_preview_is_read_only_and_rejects_changed_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_run(tmp_path, monkeypatch)
    request = {"finding_id": "F-1", "scope": "Review the owned source only"}
    preview = await controller.handle("blue.handoff_preview", request)
    assert preview["status"] == "pending_stage"
    assert preview["finding_title"] == "Owned finding"
    assert preview["source_sha256"] in preview["finding_evidence"]
    assert preview["phrase"].startswith("STAGE ")
    assert not (tmp_path / "runs" / "handoffs").exists()
    with pytest.raises(ValueError, match="does not match"):
        await controller.handle("blue.handoff_stage", {"phrase": "STAGE wrong"})

    findings_path = Path(controller.blue_preview["manifest"]).parent / "vulnerabilities.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    findings[0]["title"] = "Changed after preview"
    findings_path.write_text(json.dumps(findings), encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        await controller.handle("blue.handoff_stage", {"phrase": preview["phrase"]})
    assert not (tmp_path / "runs" / "handoffs").exists()


@pytest.mark.asyncio
async def test_handoff_requires_scoped_request_and_matched_local_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_run(tmp_path, monkeypatch)
    for request, message in [
        ({"finding_id": "F-1", "scope": " "}, "scope"),
        ({"finding_id": "F-1", "scope": "Review", "model": "openai/local"}, "both"),
        (
            {"finding_id": "F-1", "scope": "Review", "model": "bad",
             "endpoint": "http://127.0.0.1:11434/v1"},
            "openai/MODEL",
        ),
        (
            {"finding_id": "F-1", "scope": "Review", "model": "openai/local",
             "endpoint": "https://example.com"},
            "loopback",
        ),
    ]:
        with pytest.raises(ValueError, match=message):
            await controller.handle("blue.handoff_preview", request)
    assert controller.blue_handoff is None


@pytest.mark.asyncio
async def test_handoff_stages_without_endpoint_and_never_launches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_run(tmp_path, monkeypatch)
    preview = await controller.handle(
        "blue.handoff_preview", {"finding_id": "F-1", "scope": "Review owned source"}
    )
    staged = await controller.handle("blue.handoff_stage", {"phrase": preview["phrase"]})
    assert staged["status"] == "staged"
    assert staged["launch_ready"] is False
    assert staged["phrase"] == ""
    assert Path(staged["staged_target"]).is_dir()
    assert Path(staged["stage_path"], "handoff.json").is_file()
    with pytest.raises(RuntimeError, match="No launch-ready"):
        await controller.handle("blue.handoff_launch", {"phrase": "STANDARD anything"})


@pytest.mark.asyncio
async def test_failed_stage_postcheck_removes_only_its_new_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_run(tmp_path, monkeypatch)
    preview = await controller.handle(
        "blue.handoff_preview", {"finding_id": "F-1", "scope": "Review owned source"}
    )
    real_stage = blue_handoff.stage_handoff
    created: list[Path] = []

    def bad_stage(*args: object, **kwargs: object) -> tuple[Path, dict[str, object]]:
        stage, record = real_stage(*args, **kwargs)
        created.append(stage)
        return stage, {**record, "scope": "changed after staging"}

    monkeypatch.setattr(blue_handoff, "stage_handoff", bad_stage)
    with pytest.raises(ValueError, match="differs from reviewed"):
        await controller.handle("blue.handoff_stage", {"phrase": preview["phrase"]})
    assert created and not created[0].exists()
    assert controller.blue_handoff["status"] == "stage_failed"


@pytest.mark.asyncio
async def test_handoff_launch_requires_second_record_bound_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_run(tmp_path, monkeypatch)
    request = {
        "finding_id": "F-1", "scope": "Review owned source",
        "model": "openai/local", "endpoint": "http://127.0.0.1:11434/v1",
    }
    preview = await controller.handle("blue.handoff_preview", request)
    staged = await controller.handle("blue.handoff_stage", {"phrase": preview["phrase"]})
    assert staged["launch_ready"] is True
    calls: list[tuple[Path, str, str, str]] = []

    def fake_launch(stage: Path, model: str, endpoint: str, *, expected_hash: str) -> int:
        calls.append((stage, model, endpoint, expected_hash))
        return 4321

    monkeypatch.setattr(blue_handoff, "launch_staged_handoff", fake_launch)
    with pytest.raises(ValueError, match="does not match"):
        await controller.handle("blue.handoff_launch", {"phrase": "STANDARD wrong"})
    assert calls == []
    result = await controller.handle("blue.handoff_launch", {"phrase": staged["phrase"]})
    assert result["pid"] == 4321
    assert calls == [(
        Path(staged["stage_path"]), "openai/local", "http://127.0.0.1:11434/v1",
        staged["record_sha256"],
    )]
