"""Runtime-observer tests never start a fixture executable."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest

from strix.interface import blue_runtime as runtime


if TYPE_CHECKING:
    from pathlib import Path


def _fixture(tmp_path: Path) -> runtime.TargetPermit:
    target = tmp_path / "owned.exe"
    data = bytearray(128)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data[0x40:0x44] = b"PE\0\0"
    target.write_bytes(data)
    return runtime.TargetPermit(
        scope_root=tmp_path,
        target=target,
        sha256=hashlib.sha256(data).hexdigest(),
        allow_launch=True,
        allow_attach=True,
    )


def test_launch_needs_hash_bound_confirmation_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = _fixture(tmp_path)
    evidence = tmp_path / "events.jsonl"
    monkeypatch.setattr(runtime, "_require_windows", lambda: None)

    def forbidden_spawn(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("No process should be started")

    monkeypatch.setattr(runtime.subprocess, "Popen", forbidden_spawn)
    with pytest.raises(runtime.RuntimeObservationError, match="acknowledge"):
        runtime.observe_runtime(permit, mode="launch", evidence_path=evidence)
    with pytest.raises(runtime.RuntimeObservationError, match="confirmation"):
        runtime.observe_runtime(
            permit, mode="launch", evidence_path=evidence, risk_acknowledged=True
        )
    phrase = runtime.launch_confirmation_phrase(permit, evidence, 5)
    with pytest.raises(runtime.RuntimeObservationError, match="SHA-256"):
        changed = runtime.TargetPermit(
            permit.scope_root, permit.target, "0" * 64, allow_launch=True
        )
        runtime.observe_runtime(
            changed,
            mode="launch",
            evidence_path=evidence,
            confirmation_phrase=phrase,
            risk_acknowledged=True,
        )
    assert not evidence.exists()


def test_confirmation_phrase_binds_evidence_path_and_timeout(tmp_path: Path) -> None:
    permit = _fixture(tmp_path)
    first = runtime.launch_confirmation_phrase(permit, tmp_path / "first.jsonl", 5)
    assert first != runtime.launch_confirmation_phrase(permit, tmp_path / "second.jsonl", 5)
    assert first != runtime.launch_confirmation_phrase(permit, tmp_path / "first.jsonl", 6)


def test_launch_writes_process_events_with_no_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    permit = _fixture(tmp_path)
    evidence = tmp_path / "events.jsonl"
    phrase = runtime.launch_confirmation_phrase(permit, evidence, 5)
    monkeypatch.setattr(runtime, "_require_windows", lambda: None)
    seen: dict[str, object] = {}

    class FakeProcess:
        pid = 4321

        def poll(self) -> int | None:
            return 0

        def terminate(self) -> None:
            raise AssertionError("Completed process must not be terminated")

    def fake_spawn(args: list[str], **kwargs: object) -> FakeProcess:
        seen["evidence_at_spawn"] = [
            json.loads(line)["event"] for line in evidence.read_text(encoding="utf-8").splitlines()
        ]
        seen["args"] = args
        seen["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(runtime.subprocess, "Popen", fake_spawn)
    result = runtime.observe_runtime(
        permit,
        mode="launch",
        evidence_path=evidence,
        timeout_seconds=5,
        confirmation_phrase=phrase,
        risk_acknowledged=True,
    )
    events = [json.loads(line) for line in evidence.read_text(encoding="utf-8").splitlines()]
    assert seen["args"] == [str(permit.target)]
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["stdin"] == runtime.subprocess.DEVNULL
    assert seen["evidence_at_spawn"] == ["host_risk_warning", "launch_requested"]
    assert [entry["event"] for entry in events] == [
        "host_risk_warning",
        "launch_requested",
        "process_started",
        "process_observation_started",
        "process_exited",
    ]
    assert all(entry["loaded_image_sha256"] is None for entry in events)
    assert all(entry["path_sha256_at_validation"] == permit.sha256 for entry in events)
    assert result.loaded_image_sha256 is None
    assert result.status == "exited" and result.exit_code == 0
    assert "network" in capsys.readouterr().err


def test_launch_timeout_terminates_only_started_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = _fixture(tmp_path)
    evidence = tmp_path / "events.jsonl"
    phrase = runtime.launch_confirmation_phrase(permit, evidence, 0.1)
    monkeypatch.setattr(runtime, "_require_windows", lambda: None)
    actions: list[str] = []

    class FakeProcess:
        pid = 4321

        def poll(self) -> None:
            actions.append("poll")

        def kill(self) -> None:
            actions.append("kill")

        def wait(self, *, timeout: int) -> int:
            actions.append(f"wait:{timeout}")
            return 1

    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_a, **_k: FakeProcess())
    result = runtime.observe_runtime(
        permit,
        mode="launch",
        evidence_path=evidence,
        timeout_seconds=0.1,
        confirmation_phrase=phrase,
        risk_acknowledged=True,
    )
    events = [json.loads(line)["event"] for line in evidence.read_text().splitlines()]
    assert result.status == "timed_out"
    assert actions[-2:] == ["kill", "wait:2"]
    assert events[-3:] == [
        "observation_timed_out",
        "launched_process_kill_requested",
        "launched_process_exited_after_kill",
    ]


def test_evidence_creation_race_prevents_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = _fixture(tmp_path)
    evidence = tmp_path / "events.jsonl"
    phrase = runtime.launch_confirmation_phrase(permit, evidence, 5)
    monkeypatch.setattr(runtime, "_require_windows", lambda: None)
    original_validate = runtime._validate_evidence_path

    def race(path: Path) -> Path:
        if path.exists():
            return path
        resolved = original_validate(path)
        resolved.write_text("occupied", encoding="utf-8")
        return resolved

    monkeypatch.setattr(runtime, "_validate_evidence_path", race)

    def forbidden_spawn(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Evidence must exist before process creation")

    monkeypatch.setattr(runtime.subprocess, "Popen", forbidden_spawn)
    with pytest.raises(FileExistsError):
        runtime.observe_runtime(
            permit,
            mode="launch",
            evidence_path=evidence,
            confirmation_phrase=phrase,
            risk_acknowledged=True,
        )
    assert evidence.read_text(encoding="utf-8") == "occupied"


def test_post_launch_path_change_is_recorded_and_process_is_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = _fixture(tmp_path)
    evidence = tmp_path / "events.jsonl"
    phrase = runtime.launch_confirmation_phrase(permit, evidence, 5)
    monkeypatch.setattr(runtime, "_require_windows", lambda: None)
    actions: list[str] = []

    class FakeProcess:
        pid = 4321

        def poll(self) -> None:
            actions.append("poll")

        def kill(self) -> None:
            actions.append("kill")

        def wait(self, *, timeout: int) -> int:
            actions.append(f"wait:{timeout}")
            return 1

    def mutate_at_spawn(*_args: object, **_kwargs: object) -> FakeProcess:
        changed = bytearray(permit.target.read_bytes())
        changed[-1] = 1
        permit.target.write_bytes(changed)
        return FakeProcess()

    monkeypatch.setattr(runtime.subprocess, "Popen", mutate_at_spawn)
    with pytest.raises(runtime.RuntimeObservationError, match="SHA-256"):
        runtime.observe_runtime(
            permit,
            mode="launch",
            evidence_path=evidence,
            confirmation_phrase=phrase,
            risk_acknowledged=True,
        )
    events = [json.loads(line)["event"] for line in evidence.read_text().splitlines()]
    assert events == [
        "host_risk_warning",
        "launch_requested",
        "process_started",
        "observation_failed",
        "launched_process_kill_requested_after_error",
        "launched_process_exited_after_error_kill",
    ]
    assert actions == ["poll", "kill", "wait:2"]


def test_launch_failure_is_recorded_without_a_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = _fixture(tmp_path)
    evidence = tmp_path / "events.jsonl"
    phrase = runtime.launch_confirmation_phrase(permit, evidence, 5)
    monkeypatch.setattr(runtime, "_require_windows", lambda: None)

    def failed_spawn(*_args: object, **_kwargs: object) -> None:
        raise OSError("Windows loader rejected fixture")

    monkeypatch.setattr(runtime.subprocess, "Popen", failed_spawn)
    with pytest.raises(OSError, match="Windows loader"):
        runtime.observe_runtime(
            permit,
            mode="launch",
            evidence_path=evidence,
            confirmation_phrase=phrase,
            risk_acknowledged=True,
        )
    events = [json.loads(line) for line in evidence.read_text().splitlines()]
    assert [entry["event"] for entry in events] == [
        "host_risk_warning",
        "launch_requested",
        "observation_failed",
    ]
    assert events[-1]["pid"] is None


def test_attach_rejects_wrong_image_without_signaling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = _fixture(tmp_path)
    monkeypatch.setattr(runtime, "_require_windows", lambda: None)
    actions: list[str] = []

    class FakeAttached:
        pid = 1234
        image_path = tmp_path / "other.exe"
        creation_filetime = 1

        def close(self) -> None:
            actions.append("close")

    monkeypatch.setattr(runtime, "_attach", lambda _pid: FakeAttached())
    with pytest.raises(runtime.RuntimeObservationError, match="image path"):
        runtime.observe_runtime(
            permit,
            mode="attach",
            pid=1234,
            evidence_path=tmp_path / "events.jsonl",
            risk_acknowledged=True,
        )
    assert actions == ["close"]
    lines = (tmp_path / "events.jsonl").read_text().splitlines()
    events = [json.loads(line)["event"] for line in lines]
    assert events == ["host_risk_warning", "attach_requested", "observation_failed"]


def test_attach_observes_exit_without_terminating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = _fixture(tmp_path)
    monkeypatch.setattr(runtime, "_require_windows", lambda: None)
    actions: list[str] = []

    class FakeAttached:
        pid = 1234
        image_path = permit.target
        creation_filetime = 42

        def poll(self) -> int:
            actions.append("poll")
            return 7

        def close(self) -> None:
            actions.append("close")

    monkeypatch.setattr(runtime, "_attach", lambda _pid: FakeAttached())
    result = runtime.observe_runtime(
        permit,
        mode="attach",
        pid=1234,
        evidence_path=tmp_path / "events.jsonl",
        risk_acknowledged=True,
    )
    assert result.status == "exited" and result.exit_code == 7
    assert result.path_sha256_at_validation == permit.sha256
    assert result.loaded_image_sha256 is None
    events = [json.loads(line) for line in result.evidence_path.read_text().splitlines()]
    assert all(entry["loaded_image_sha256"] is None for entry in events)
    assert all(entry["path_sha256_at_validation"] == permit.sha256 for entry in events)
    assert events[2]["image_identity"] == (
        "path hash at validation time; loaded image bytes unverified"
    )
    assert actions == ["poll", "close"]
