"""Bounded Windows PE process observation for explicitly permitted local fixtures.

This module does not provide isolation. A launched target can access the network,
write files or registry keys, start child processes, and change the host. Attach
only opens a process for query and wait access. No exploit or patch operation is
available here. The caller must show WARNING and obtain the launch confirmation
phrase from the operator before calling :func:`observe_runtime`.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from contextlib import suppress
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal


WARNING = (
    "This PE may contact the network, write files or registry keys, "
    "start child processes, and change this Windows host. This observation "
    "does not isolate or contain the target."
)
_MAX_TARGET_BYTES = 256 * 1024 * 1024
_MAX_SECONDS = 30.0
_SAMPLE_SECONDS = 0.2


class RuntimeObservationError(ValueError):
    """The requested observation failed validation or execution."""


@dataclass(frozen=True)
class TargetPermit:
    """One hash-pinned PE path in an operator-approved local scope."""

    scope_root: Path
    target: Path
    sha256: str
    allow_launch: bool = False
    allow_attach: bool = False


@dataclass(frozen=True)
class ObservationResult:
    mode: Literal["launch", "attach"]
    pid: int
    path_sha256_at_validation: str
    loaded_image_sha256: None
    status: Literal["exited", "timed_out"]
    exit_code: int | None
    evidence_path: Path
    elapsed_seconds: float


def _require_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeObservationError("Runtime observation requires Windows.")


def _regular_path(path: Path) -> Path:
    if not path.is_absolute():
        raise RuntimeObservationError("Scope and target paths must be absolute.")
    for item in (path, *path.parents):
        if item.is_symlink() or item.is_junction():
            raise RuntimeObservationError("Reparse points are not allowed in target paths.")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise RuntimeObservationError("Target must be a regular file.")
    return resolved


def _validate_target(permit: TargetPermit) -> Path:  # noqa: PLR0912
    if not re.fullmatch(r"[0-9a-fA-F]{64}", permit.sha256):
        raise RuntimeObservationError("Expected SHA-256 must be 64 hexadecimal characters.")
    if not permit.scope_root.is_absolute():
        raise RuntimeObservationError("Scope path must be absolute.")
    for item in (permit.scope_root, *permit.scope_root.parents):
        if item.is_symlink() or item.is_junction():
            raise RuntimeObservationError("Reparse points are not allowed in scope paths.")
    scope = permit.scope_root.resolve(strict=True)
    if not scope.is_dir():
        raise RuntimeObservationError("Scope must be a directory.")
    target = _regular_path(permit.target)
    if scope not in target.parents:
        raise RuntimeObservationError("Target is outside the permitted scope.")
    if target.suffix.lower() != ".exe":
        raise RuntimeObservationError("This first runtime observer supports PE .exe files only.")
    if target.stat().st_size > _MAX_TARGET_BYTES:
        raise RuntimeObservationError("Target exceeds the 256 MiB limit.")
    digest = hashlib.sha256()
    with target.open("rb") as stream:
        header = stream.read(4096)
        if len(header) < 64 or header[:2] != b"MZ":
            raise RuntimeObservationError("Target is not a PE executable.")
        pe_offset = int.from_bytes(header[0x3C:0x40], "little")
        if pe_offset > _MAX_TARGET_BYTES - 4:
            raise RuntimeObservationError("Target has an invalid PE offset.")
        stream.seek(pe_offset)
        if stream.read(4) != b"PE\0\0":
            raise RuntimeObservationError("Target is not a PE executable.")
        stream.seek(0)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != permit.sha256.lower():
        raise RuntimeObservationError("Target SHA-256 does not match the permit.")
    return target


def launch_confirmation_phrase(
    permit: TargetPermit, evidence_path: Path, timeout_seconds: float
) -> str:
    """Return the phrase the operator must type for this exact launch request."""
    target = _validate_target(permit)
    seconds = _validate_timeout(timeout_seconds)
    evidence = _validate_evidence_path(evidence_path)
    scope = permit.scope_root.resolve(strict=True)
    payload = json.dumps(
        [str(scope), str(target), permit.sha256.lower(), str(evidence), seconds, "launch"],
        separators=(",", ":"),
    ).encode("utf-8")
    return "LAUNCH " + hashlib.sha256(payload).hexdigest()[:20].upper()


def _validate_timeout(value: float) -> float:
    if not isinstance(value, (int, float)) or not 0.1 <= value <= _MAX_SECONDS:
        raise RuntimeObservationError("Observation time must be between 0.1 and 30 seconds.")
    return float(value)


def _validate_evidence_path(path: Path) -> Path:
    if not path.is_absolute() or path.suffix.lower() != ".jsonl":
        raise RuntimeObservationError("Evidence path must be an absolute .jsonl path.")
    if path.exists() or path.is_symlink() or path.is_junction():
        raise RuntimeObservationError("Evidence path must be new.")
    parent = path.parent
    if not parent.is_dir():
        raise RuntimeObservationError("Evidence parent directory must exist.")
    for item in (parent, *parent.parents):
        if item.is_symlink() or item.is_junction():
            raise RuntimeObservationError("Reparse points are not allowed in evidence paths.")
    return parent.resolve(strict=True) / path.name


class _AttachedProcess:
    def __init__(self, pid: int) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        self._kernel32 = kernel32
        self._handle = kernel32.OpenProcess(0x1000 | 0x100000, 0, pid)
        if not self._handle:
            raise RuntimeObservationError(f"Cannot query PID {pid}.")
        self.pid = pid
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        if not kernel32.QueryFullProcessImageNameW(self._handle, 0, buffer, ctypes.byref(size)):
            self.close()
            raise RuntimeObservationError("Cannot read attached process image path.")
        self.image_path = Path(buffer.value)
        created = wintypes.FILETIME()
        exited = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        if not kernel32.GetProcessTimes(
            self._handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            self.close()
            raise RuntimeObservationError("Cannot read attached process creation time.")
        self.creation_filetime = (created.dwHighDateTime << 32) | created.dwLowDateTime

    def poll(self) -> int | None:
        state = self._kernel32.WaitForSingleObject(self._handle, 0)
        if state == 0x102:  # WAIT_TIMEOUT
            return None
        if state != 0:  # WAIT_OBJECT_0
            raise RuntimeObservationError("Cannot wait on attached process.")
        code = wintypes.DWORD()
        if not self._kernel32.GetExitCodeProcess(self._handle, ctypes.byref(code)):
            raise RuntimeObservationError("Cannot read attached process exit code.")
        return int(code.value)

    def close(self) -> None:
        self._kernel32.CloseHandle(self._handle)


def _attach(pid: int) -> _AttachedProcess:
    return _AttachedProcess(pid)


def observe_runtime(  # noqa: PLR0912, PLR0915
    permit: TargetPermit,
    *,
    mode: Literal["launch", "attach"],
    evidence_path: Path,
    timeout_seconds: float = 5.0,
    pid: int | None = None,
    confirmation_phrase: str | None = None,
    risk_acknowledged: bool = False,
) -> ObservationResult:
    """Observe one hash-pinned PE process and write a new JSONL evidence file.

    Launch starts the permitted .exe with no arguments or stdin and discards its
    output. On timeout it forcibly terminates that process with a bounded wait.
    Child processes can outlive it. Attach only queries the PID, image path,
    creation time and exit state; it never sends a signal to that process. The
    SHA-256 is for the current file at the path, not verified loaded image bytes.
    File replacement between the checks and CreateProcess cannot be ruled out.
    """
    _require_windows()
    if mode not in {"launch", "attach"}:
        raise RuntimeObservationError("Mode must be launch or attach.")
    if not risk_acknowledged:
        raise RuntimeObservationError("Operator must acknowledge the host risk warning.")
    seconds = _validate_timeout(timeout_seconds)
    target = _validate_target(permit)
    evidence = _validate_evidence_path(evidence_path)
    if mode == "launch":
        if not permit.allow_launch or pid is not None:
            raise RuntimeObservationError("Permit does not allow this launch request.")
        expected = launch_confirmation_phrase(permit, evidence, seconds)
        if confirmation_phrase != expected:
            raise RuntimeObservationError("Launch confirmation phrase does not match this request.")
    elif not permit.allow_attach or not isinstance(pid, int) or pid <= 0:
        raise RuntimeObservationError("Permit does not allow this attach request.")
    print(WARNING, file=sys.stderr)  # noqa: T201
    process: subprocess.Popen[bytes] | _AttachedProcess | None = None
    launched: subprocess.Popen[bytes] | None = None
    attached: _AttachedProcess | None = None
    started = time.monotonic()
    sequence = 0
    exit_code: int | None = None
    status: Literal["exited", "timed_out"] = "timed_out"
    with evidence.open("x", encoding="utf-8") as stream:

        def event(kind: str, *, sync: bool = False, **details: object) -> None:
            nonlocal sequence
            sequence += 1
            record = {
                "sequence": sequence,
                "time_utc": datetime.now(UTC).isoformat(),
                "event": kind,
                "mode": mode,
                "pid": process.pid if process is not None else None,
                "target": str(target),
                "path_sha256_at_validation": permit.sha256.lower(),
                "loaded_image_sha256": None,
                **details,
            }
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            if sync:
                os.fsync(stream.fileno())

        event("host_risk_warning", message=WARNING)
        try:
            if mode == "attach":
                assert pid is not None
                event("attach_requested", sync=True)
                attached = _attach(pid)
                process = attached
                try:
                    image_path = attached.image_path.resolve(strict=True)
                except OSError as exc:
                    raise RuntimeObservationError("PID image path is unavailable.") from exc
                if image_path != target:
                    raise RuntimeObservationError(  # noqa: TRY301
                        "PID image path does not match the permitted target."
                    )
                _validate_target(permit)
            else:
                _validate_target(permit)
                event("launch_requested", sync=True)
                launched = subprocess.Popen(  # noqa: S603
                    [str(target)],
                    cwd=str(permit.scope_root.resolve(strict=True)),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    close_fds=True,
                )
                process = launched
                event("process_started")
                _validate_target(permit)

            assert process is not None
            event(
                "process_observation_started",
                creation_filetime=getattr(process, "creation_filetime", None),
                image_identity="path hash at validation time; loaded image bytes unverified",
            )
            while True:
                exit_code = process.poll()
                if exit_code is not None:
                    status = "exited"
                    event("process_exited", exit_code=exit_code)
                    break
                elapsed = time.monotonic() - started
                if elapsed >= seconds:
                    event("observation_timed_out", elapsed_seconds=round(elapsed, 3))
                    break
                event("process_alive", elapsed_seconds=round(elapsed, 3))
                time.sleep(min(_SAMPLE_SECONDS, seconds - elapsed))
            if launched is not None and status == "timed_out":
                event("launched_process_kill_requested")
                launched.kill()
                try:
                    exit_code = launched.wait(timeout=2)
                    event("launched_process_exited_after_kill", exit_code=exit_code)
                except subprocess.TimeoutExpired:
                    event("launched_process_kill_wait_timed_out")
        except BaseException as exc:
            with suppress(OSError):
                event("observation_failed", error_type=type(exc).__name__, error=str(exc))
            if launched is not None and launched.poll() is None:
                with suppress(OSError):
                    event("launched_process_kill_requested_after_error")
                try:
                    launched.kill()
                    cleanup_code = launched.wait(timeout=2)
                    with suppress(OSError):
                        event("launched_process_exited_after_error_kill", exit_code=cleanup_code)
                except (OSError, subprocess.TimeoutExpired) as cleanup_exc:
                    with suppress(OSError):
                        event(
                            "launched_process_cleanup_unconfirmed",
                            error_type=type(cleanup_exc).__name__,
                        )
            raise
        finally:
            if attached is not None:
                attached.close()
    assert process is not None
    return ObservationResult(
        mode=mode,
        pid=process.pid,
        path_sha256_at_validation=permit.sha256.lower(),
        loaded_image_sha256=None,
        status=status,
        exit_code=exit_code,
        evidence_path=evidence,
        elapsed_seconds=round(time.monotonic() - started, 3),
    )
