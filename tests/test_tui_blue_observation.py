"""TUI runtime approval tests never start an executable."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from strix.interface import blue_runtime
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


def _pe() -> bytes:
    data = bytearray(128)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data[0x40:0x44] = b"PE\0\0"
    return bytes(data)


async def _completed_blue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TuiController:
    target = tmp_path / "owned.exe"
    target.write_bytes(_pe())
    monkeypatch.setenv("STRIX_RUNS_DIR", str(tmp_path / "runs"))
    controller = TuiController(_args())
    preview = await controller.handle("setup.blue_prepare", {"target": str(target)})
    manifest_path = Path(preview["manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["status"] = "completed"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    controller.setup_mode = False
    controller.scan_started = True
    controller.scan_state = "completed"
    return controller


@pytest.mark.asyncio
async def test_launch_requires_exact_preview_phrase_and_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_blue(tmp_path, monkeypatch)
    calls: list[tuple[blue_runtime.TargetPermit, dict[str, object]]] = []

    def fake_observe(
        permit: blue_runtime.TargetPermit, **kwargs: object
    ) -> blue_runtime.ObservationResult:
        calls.append((permit, kwargs))
        evidence = kwargs["evidence_path"]
        assert isinstance(evidence, Path)
        evidence.write_text('{"event":"mock"}\n', encoding="utf-8")
        return blue_runtime.ObservationResult(
            mode="launch", pid=4321, path_sha256_at_validation=permit.sha256,
            loaded_image_sha256=None, status="exited", exit_code=0,
            evidence_path=evidence, elapsed_seconds=0.1,
        )

    monkeypatch.setattr(blue_runtime, "observe_runtime", fake_observe)
    preview = await controller.handle(
        "blue.observe_preview", {"mode": "launch", "path": "owned.exe", "timeout_seconds": 3}
    )
    assert preview["status"] == "pending"
    assert preview["mode"] == "launch"
    assert preview["sha256"] == hashlib.sha256(_pe()).hexdigest()
    assert preview["phrase"].startswith("LAUNCH ")
    assert preview["warning"] == blue_runtime.WARNING
    assert not Path(preview["evidence"]).exists()
    with pytest.raises(ValueError, match="does not match"):
        await controller.handle("blue.observe_confirm", {"phrase": "LAUNCH wrong"})
    assert calls == []
    with pytest.raises(RuntimeError, match="current runtime request"):
        await controller.handle(
            "blue.observe_preview", {"mode": "launch", "path": "owned.exe"}
        )
    await controller.handle("blue.observe_confirm", {"phrase": preview["phrase"]})
    assert controller._blue_observation_task is not None
    await asyncio.wait_for(controller._blue_observation_task, timeout=5)
    assert len(calls) == 1
    permit, kwargs = calls[0]
    assert permit.allow_launch is True and permit.allow_attach is False
    assert kwargs["risk_acknowledged"] is True
    assert kwargs["confirmation_phrase"] == preview["phrase"]
    assert controller.snapshot()["blue_observation"]["status"] == "completed"
    assert Path(preview["evidence"]).is_file()
    events = [
        json.loads(line)
        for line in (Path(preview["evidence"]).parent / "blue-events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert events[-1]["kind"] == "runtimeObservation"
    assert "PID 4321: exited" in events[-1]["summary"]


@pytest.mark.asyncio
async def test_attach_preview_binds_pid_and_cancel_starts_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_blue(tmp_path, monkeypatch)

    def forbidden_observe(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("No process should be observed")

    monkeypatch.setattr(blue_runtime, "observe_runtime", forbidden_observe)
    monkeypatch.setattr(
        "strix.interface.tui.backend.controller.uuid4",
        lambda: SimpleNamespace(hex="d" * 32),
    )
    first = await controller.handle(
        "blue.observe_preview",
        {"mode": "attach", "path": "owned.exe", "pid": 100, "timeout_seconds": 2},
    )
    assert first["phrase"].startswith("ATTACH ")
    assert first["pid"] == 100
    await controller.handle("blue.observe_cancel", {})
    second = await controller.handle(
        "blue.observe_preview",
        {"mode": "attach", "path": "owned.exe", "pid": 101, "timeout_seconds": 2},
    )
    assert first["phrase"] != second["phrase"]
    assert first["evidence"] == second["evidence"]
    assert controller._blue_observation_task is None
    assert not Path(first["evidence"]).exists()


@pytest.mark.asyncio
async def test_runtime_preview_requires_completed_included_pe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_blue(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="included"):
        await controller.handle(
            "blue.observe_preview", {"mode": "launch", "path": "outside.exe"}
        )
    with pytest.raises(ValueError, match="positive PID"):
        await controller.handle(
            "blue.observe_preview", {"mode": "attach", "path": "owned.exe", "pid": 0}
        )
    controller.scan_state = "running"
    with pytest.raises(RuntimeError, match="Finish a Blue run"):
        await controller.handle(
            "blue.observe_preview", {"mode": "launch", "path": "owned.exe"}
        )


@pytest.mark.asyncio
async def test_target_change_after_preview_blocks_runtime_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_blue(tmp_path, monkeypatch)

    def forbidden_observe(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("No process should be observed")

    monkeypatch.setattr(blue_runtime, "observe_runtime", forbidden_observe)
    preview = await controller.handle(
        "blue.observe_preview", {"mode": "launch", "path": "owned.exe"}
    )
    Path(preview["path"]).write_bytes(_pe() + b"changed")
    with pytest.raises(ValueError, match="snapshot changed"):
        await controller.handle("blue.observe_confirm", {"phrase": preview["phrase"]})
    assert not Path(preview["evidence"]).exists()


@pytest.mark.asyncio
async def test_manifest_cannot_redirect_runtime_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = await _completed_blue(tmp_path, monkeypatch)
    manifest_path = Path(controller.blue_preview["manifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["input_snapshot"] = str(tmp_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest changed"):
        await controller.handle(
            "blue.observe_preview", {"mode": "launch", "path": "owned.exe"}
        )
