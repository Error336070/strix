from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import pytest

from strix.interface.tui.backend.controller import TuiController


def _args() -> argparse.Namespace:
    return argparse.Namespace(
        needs_setup=True,
        targets_info=[],
        instruction=None,
        scan_mode="deep",
        max_budget_usd=None,
        max_turns=500,
        scope_mode="auto",
        diff_base=None,
    )


@pytest.mark.asyncio
async def test_blue_preview_requires_matching_hash_phrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())

    preview = await controller.handle("setup.blue_prepare", {"target": str(target)})
    manifest_path = Path(preview["manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert preview["target"] == str(target)
    assert preview["file_count"] == 1
    assert preview["first_sha256"] == manifest["files"][0]["sha256"]
    assert len(preview["scope_sha256"]) == 64
    assert controller.snapshot()["blue_preview"]["scope_sha256"] == preview["scope_sha256"]
    assert controller.snapshot()["scan_state"] == "setup"

    with pytest.raises(ValueError, match="does not match"):
        await controller.handle("setup.blue_confirm", {"phrase": "RUN deadbeef"})
    assert controller.snapshot()["scan_started"] is False
    assert manifest["status"] == "prepared"

    called: list[tuple[Path, str]] = []

    def fake_run(path: Path, *, confirmed_phrase: str) -> None:
        called.append((path, confirmed_phrase))

    monkeypatch.setattr("strix.interface.blue._run_prepared", fake_run)
    phrase = f"RUN {preview['scope_sha256'][:8]}"
    result = await controller.handle("setup.blue_confirm", {"phrase": phrase})
    assert result["started"] is True
    assert controller.snapshot()["setup_mode"] is False
    assert controller._blue_task is not None
    await asyncio.wait_for(controller._blue_task, timeout=5)
    assert called == [(manifest_path, f"RUN {preview['first_sha256'][:8]}")]
    assert controller.snapshot()["scan_state"] == "completed"


@pytest.mark.asyncio
async def test_blue_preview_shows_selected_local_route_and_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.dll"
    target.write_bytes(b"MZ" + b"\0" * 126)
    helper = tmp_path / "pe-audit.exe"
    helper.write_bytes(b"owned helper")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())
    preview = await controller.handle(
        "setup.blue_prepare",
        {
            "target": str(target), "case_id": "owned-case", "provider": "local",
            "model": "local-audit", "endpoint": "http://127.0.0.1:11434/v1",
            "approval": "deny", "pe_audit": str(helper),
        },
    )
    assert preview["case_id"] == "owned-case"
    assert preview["provider"] == "local-openai-compatible"
    assert preview["model"] == "local-audit"
    assert preview["endpoint"] == "http://127.0.0.1:11434/v1"
    assert preview["pe_audit"]["path"] == str(helper)


@pytest.mark.asyncio
async def test_blue_preview_cancel_does_not_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())
    preview = await controller.handle("setup.blue_prepare", {"target": str(target)})
    assert await controller.handle("setup.blue_cancel", {}) == {"cancelled": True}
    assert controller.snapshot()["blue_preview"] is None
    assert not Path(preview["manifest"]).parent.exists()
    with pytest.raises(RuntimeError, match="No Blue preview"):
        await controller.handle("setup.blue_confirm", {"phrase": "RUN deadbeef"})


@pytest.mark.asyncio
async def test_blue_cancel_preserves_changed_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())
    preview = await controller.handle("setup.blue_prepare", {"target": str(target)})
    output = Path(preview["manifest"]).parent
    (output / "operator-note.txt").write_text("keep this", encoding="utf-8")
    with pytest.raises(ValueError, match="additional files"):
        await controller.handle("setup.blue_cancel", {})
    assert output.is_dir()
    assert (output / "operator-note.txt").read_text(encoding="utf-8") == "keep this"
    assert controller.snapshot()["blue_preview"] is not None
