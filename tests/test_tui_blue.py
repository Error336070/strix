from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from strix.interface.blue import run_blue
from strix.interface.tui.backend.controller import TuiController
from strix.interface.viewer import server


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


def test_blue_command_opens_tui_without_standard_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[argparse.Namespace] = []

    async def fake_run_tui(args: argparse.Namespace) -> None:
        captured.append(args)

    monkeypatch.delenv("STRIX_LLM", raising=False)
    monkeypatch.setattr("strix.interface.blue.terminal_attached", lambda: True)
    monkeypatch.setattr("strix.interface.blue.run_tui", fake_run_tui)
    assert run_blue([]) == 0
    assert len(captured) == 1
    assert captured[0].needs_setup is True
    assert captured[0].blue_mode is True


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

    def fake_run(path: Path, *, confirmed_phrase: str, expected_manifest_sha256: str) -> str:
        called.append((path, confirmed_phrase))
        assert expected_manifest_sha256 == preview["manifest_sha256"]
        return "completed"

    monkeypatch.setattr("strix.interface.blue._run_prepared", fake_run)
    phrase = f"RUN {preview['manifest_sha256'][:8]}"
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
    monkeypatch.setenv("STRIX_PE_AUDIT_HELPER", str(helper))
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
async def test_blue_preview_auto_selects_pinned_helper_or_warns_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.dll"
    target.write_bytes(b"MZ" + b"\0" * 126)
    helper = tmp_path / "pe-audit.exe"
    helper.write_bytes(b"owned helper")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("STRIX_PE_AUDIT_HELPER", str(helper))
    with_helper = TuiController(_args())
    preview = await with_helper.handle("setup.blue_prepare", {"target": str(target)})
    assert preview["pe_audit"]["path"] == str(helper)
    assert preview["binary_without_helper"] is False

    monkeypatch.delenv("STRIX_PE_AUDIT_HELPER")
    without_helper = TuiController(_args())
    preview = await without_helper.handle("setup.blue_prepare", {"target": str(target)})
    assert preview["pe_audit"] is None
    assert preview["binary_without_helper"] is True


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
async def test_blue_confirm_rejects_manifest_settings_changed_after_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())
    preview = await controller.handle("setup.blue_prepare", {"target": str(target)})
    manifest_path = Path(preview["manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["model"] = "changed-model"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest changed since preview"):
        await controller.handle(
            "setup.blue_confirm", {"phrase": f"RUN {preview['manifest_sha256'][:8]}"}
        )
    assert controller.scan_started is False
    assert controller._blue_task is None


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["failed", "interrupted"])
async def test_blue_run_reports_noncompleted_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())
    preview = await controller.handle("setup.blue_prepare", {"target": str(target)})

    def fake_run(_path: Path, *, confirmed_phrase: str, expected_manifest_sha256: str) -> str:
        assert confirmed_phrase == f"RUN {preview['first_sha256'][:8]}"
        assert expected_manifest_sha256 == preview["manifest_sha256"]
        return outcome

    monkeypatch.setattr("strix.interface.blue._run_prepared", fake_run)
    await controller.handle(
        "setup.blue_confirm", {"phrase": f"RUN {preview['manifest_sha256'][:8]}"}
    )
    assert controller._blue_task is not None
    await asyncio.wait_for(controller._blue_task, timeout=5)
    assert controller.scan_state == outcome
    assert controller.error is not None


@pytest.mark.asyncio
async def test_blue_run_opens_shared_viewer_from_its_manifest_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())
    preview = await controller.handle("setup.blue_prepare", {"target": str(target)})
    controller.setup_mode = False
    controller.scan_started = True
    opened: list[tuple[Path, bool, object]] = []
    httpd = SimpleNamespace(shutdown=lambda: None, server_close=lambda: None)

    def fake_serve(run_dir: Path, *, open_browser: bool, steer_handler: object):
        opened.append((run_dir, open_browser, steer_handler))
        return httpd, "http://127.0.0.1:12345", "test-token"

    monkeypatch.setattr(server, "bundle_is_built", lambda: True)
    monkeypatch.setattr(server, "serve", fake_serve)
    monkeypatch.setattr(server, "authorized_url", lambda url, token: f"{url}?token={token}")
    result = await controller.handle("viewer.open", {})
    assert result["status"] == "running"
    assert opened == [(Path(preview["manifest"]).parent, True, None)]
    controller.close_viewer()


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
