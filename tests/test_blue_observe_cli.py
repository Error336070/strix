"""The Blue CLI must require an operator decision before runtime work."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from strix.interface import blue, blue_runtime


def _prepared_exe(tmp_path: Path) -> Path:
    target = tmp_path / "owned.exe"
    data = bytearray(128)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data[0x40:0x44] = b"PE\0\0"
    target.write_bytes(data)
    output = tmp_path / "runs" / "blue-owned"
    blue.prepare_blue(target, output)
    return output / "manifest.json"


def test_observe_launch_requires_typed_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _prepared_exe(tmp_path)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        blue_runtime, "launch_confirmation_phrase", lambda *_args: "LAUNCH REVIEWED"
    )

    def fake_observe(_permit: object, **kwargs: object) -> SimpleNamespace:
        calls.append(kwargs)
        Path(kwargs["evidence_path"]).write_text('{"event":"process_exited"}\n', encoding="utf-8")
        return SimpleNamespace(pid=4321, status="exited")

    monkeypatch.setattr(blue_runtime, "observe_runtime", fake_observe)
    monkeypatch.setattr("builtins.input", lambda _prompt: "wrong phrase")
    assert blue.run_blue(["observe", str(manifest), "--mode", "launch"]) == 2
    assert calls == []

    monkeypatch.setattr("builtins.input", lambda _prompt: "LAUNCH REVIEWED")
    assert blue.run_blue(["observe", str(manifest), "--mode", "launch"]) == 0
    assert calls[0]["risk_acknowledged"] is True
    assert calls[0]["confirmation_phrase"] == "LAUNCH REVIEWED"
    events = [
        json.loads(line)
        for line in (manifest.parent / "blue-events.jsonl").read_text().splitlines()
    ]
    assert events[-1]["kind"] == "runtimeObservation"
    assert "PID 4321" in events[-1]["summary"]


def test_observe_rejects_changed_target_before_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _prepared_exe(tmp_path)
    (tmp_path / "owned.exe").write_bytes(b"changed")
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: pytest.fail("Invalid target must not prompt for approval")
    )
    assert blue.run_blue(["observe", str(manifest), "--mode", "launch"]) == 2


def test_observe_attach_requires_pid(tmp_path: Path) -> None:
    manifest = _prepared_exe(tmp_path)
    assert blue.run_blue(["observe", str(manifest), "--mode", "attach"]) == 2
