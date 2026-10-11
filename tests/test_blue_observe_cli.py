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
    manifest_path = output / "manifest.json"
    record = json.loads(manifest_path.read_text(encoding="utf-8"))
    record["status"] = "completed"
    manifest_path.write_text(json.dumps(record), encoding="utf-8")
    return manifest_path


def test_observe_launch_requires_typed_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _prepared_exe(tmp_path)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        blue_runtime, "launch_confirmation_phrase", lambda *_args: "LAUNCH REVIEWED"
    )

    def fake_observe(permit: blue_runtime.TargetPermit, **kwargs: object) -> SimpleNamespace:
        assert permit.target == manifest.parent / "inputs" / "owned.exe"
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


def test_observe_rejects_changed_snapshot_before_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _prepared_exe(tmp_path)
    (manifest.parent / "inputs" / "owned.exe").write_bytes(b"changed")
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: pytest.fail("Invalid target must not prompt for approval")
    )
    assert blue.run_blue(["observe", str(manifest), "--mode", "launch"]) == 2


def test_observe_requires_completed_run_before_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _prepared_exe(tmp_path)
    record = json.loads(manifest.read_text(encoding="utf-8"))
    record["status"] = "prepared"
    manifest.write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: pytest.fail("Prepared run must not prompt")
    )
    assert blue.run_blue(["observe", str(manifest), "--mode", "launch"]) == 2


def test_observe_attach_requires_pid(tmp_path: Path) -> None:
    manifest = _prepared_exe(tmp_path)
    assert blue.run_blue(["observe", str(manifest), "--mode", "attach"]) == 2


def test_observe_rejects_nonfinite_timeout_before_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _prepared_exe(tmp_path)
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: pytest.fail("Invalid timeout must not prompt")
    )
    with pytest.raises(SystemExit) as exit_info:
        blue.run_blue(
            ["observe", str(manifest), "--mode", "attach", "--pid", "1", "--timeout", "nan"]
        )
    assert exit_info.value.code == 2
