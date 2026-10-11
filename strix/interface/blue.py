"""Operator-led, local-only Blue audits. This module bypasses Strix scan tools."""

# ruff: noqa: T201 - This module is an interactive CLI.

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import secrets
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.core.paths import runs_base_dir
from strix.interface.blue_codex import run_codex
from strix.interface.blue_findings import save_findings
from strix.interface.blue_local import run_local, validate_loopback_endpoint
from strix.interface.blue_pe import trusted_helper_record, validate_helper_record
from strix.interface.cli_args import parse_arguments, terminal_attached
from strix.interface.interactive import run_tui


_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", "bin", "obj"}
_MAX_FILES = 500
_MAX_TOTAL_BYTES = 64 * 1024 * 1024


class BlueError(Exception):
    """An invalid or unsafe Blue run request."""


def _contained(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(target: Path) -> list[dict[str, Any]]:  # noqa: PLR0912
    """Hash a bounded, symlink-free target without executing its contents."""
    if not target.exists() or target.is_symlink() or target.is_junction():
        raise BlueError("Target must exist and must not be a symlink.")
    target = target.resolve(strict=True)
    paths: list[Path] = []
    if target.is_file():
        paths = [target]
    elif target.is_dir():
        for root, dirs, files in os.walk(target, followlinks=False):
            root_path = Path(root)
            if root_path.is_symlink():
                raise BlueError(f"Symlinked directory is outside scope: {root_path}")
            for name in list(dirs):
                directory = root_path / name
                if directory.is_symlink() or directory.is_junction():
                    raise BlueError(f"Symlinked directory is outside scope: {directory}")
                if name in _SKIP_DIRS:
                    dirs.remove(name)
            for name in files:
                path = root_path / name
                if path.is_symlink() or not path.is_file():
                    raise BlueError(f"Unsupported file or symlink: {path}")
                paths.append(path)
                if len(paths) > _MAX_FILES:
                    raise BlueError(f"Target exceeds {_MAX_FILES} files. Choose a smaller scope.")
    else:
        raise BlueError("Target must be a regular file or directory.")
    if not paths:
        raise BlueError("Target contains no included files.")
    total = 0
    entries: list[dict[str, Any]] = []
    for path in sorted(paths, key=lambda item: str(item).casefold()):
        size = path.stat().st_size
        total += size
        if total > _MAX_TOTAL_BYTES:
            raise BlueError("Target exceeds the 64 MiB inventory limit. Choose a smaller scope.")
        entries.append(
            {
                "path": str(path.relative_to(target)) if target.is_dir() else target.name,
                "size": size,
                "sha256": _file_hash(path),
            }
        )
    return entries


def build_manifest(
    target: Path,
    output: Path,
    model: str,
    approval: str,
    provider: str = "codex",
    endpoint: str | None = None,
    case_id: str | None = None,
    pe_audit: Path | None = None,
) -> dict[str, Any]:
    if target.is_symlink() or target.is_junction():
        raise BlueError("Target must not be a symlink or junction.")
    if str(target).startswith(("\\\\", "//")) or str(output).startswith(("\\\\", "//")):
        raise BlueError("UNC and device paths are outside the local Blue scope.")
    target = target.resolve(strict=True)
    output = output.parent.resolve(strict=False) / output.name
    if str(target).startswith(("\\\\", "//")) or str(output).startswith(("\\\\", "//")):
        raise BlueError("UNC and device paths are outside the local Blue scope.")
    if _contained(output, target) or _contained(target, output):
        raise BlueError("Output must be outside the target and its parent directories.")
    if output.exists():
        raise BlueError("Output directory already exists; choose a fresh path.")
    if provider == "local":
        if approval != "deny" or not endpoint:
            raise BlueError("Local provider requires --approval deny and a loopback --endpoint.")
        validate_loopback_endpoint(endpoint)
    elif provider != "codex" or endpoint is not None:
        raise BlueError("Codex provider does not accept a local endpoint.")
    entries = inventory(target)
    tool_record = None
    if pe_audit is not None:
        tool_record = trusted_helper_record(pe_audit, target, output)
    manifest: dict[str, Any] = {
        "schema": "strix-blue-local-v1",
        "created_utc": datetime.now(UTC).isoformat(),
        "run_id": output.name,
        "case_id": case_id or output.name,
        "parent_run_id": None,
        "pe_audit": tool_record,
        "target": str(target),
        "output": str(output),
        "input_snapshot": str(output / "inputs"),
        "files": entries,
        "model": model,
        "provider": "codex-subscription" if provider == "codex" else "local-openai-compatible",
        "endpoint": endpoint,
        "cyber_access_program": "daybreakBlue" if provider == "codex" else None,
        "approval": approval,
        "sandbox": {"type": "readOnly", "networkAccess": False},
        "operations": ["static-read", "analysis", "report"],
        "limits": {"seconds": 900, "max_files": _MAX_FILES, "max_bytes": _MAX_TOTAL_BYTES},
        "strix_native_tools": [],
        "status": "prepared",
    }
    return manifest


def _json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _event(output: Path, kind: str, summary: str) -> None:
    entry = {"timestamp": datetime.now(UTC).isoformat(), "kind": kind, "summary": summary}
    with (output / "blue-events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _copy_snapshot(manifest: dict[str, Any]) -> None:
    target = Path(manifest["target"])
    root = Path(manifest["input_snapshot"])
    for entry in manifest["files"]:
        source = target / entry["path"] if target.is_dir() else target
        destination = root / entry["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as input_stream, destination.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
        if (
            destination.stat().st_size != entry["size"]
            or _file_hash(destination) != entry["sha256"]
        ):
            raise BlueError(f"Target changed while copying: {entry['path']}")


def prepare_blue(
    target: Path,
    output: Path,
    model: str = "gpt-6-sol",
    approval: str = "deny",
    provider: str = "codex",
    endpoint: str | None = None,
    case_id: str | None = None,
    pe_audit: Path | None = None,
) -> dict[str, Any]:
    """Prepare the same hash-checked snapshot for CLI and TUI callers."""
    manifest = build_manifest(
        target, output, model, approval, provider, endpoint, case_id, pe_audit
    )
    output = Path(manifest["output"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=False)
    _copy_snapshot(manifest)
    _json(output / "manifest.json", manifest)
    _event(output, "prepared", f"{len(manifest['files'])} files hash checked")
    return manifest


def discard_prepared_blue(manifest_path: Path, scope_sha256: str) -> None:
    """Remove only a complete, unchanged TUI preview beneath the runs root."""
    root = runs_base_dir().resolve(strict=True)
    output = manifest_path.parent.resolve(strict=True)
    if output.parent != root or manifest_path.resolve(strict=True) != output / "manifest.json":
        raise BlueError("Prepared Blue output is outside the configured runs root.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files")
    if (
        manifest.get("schema") != "strix-blue-local-v1"
        or manifest.get("status") != "prepared"
        or not isinstance(files, list)
        or Path(manifest.get("output", "")).resolve() != output
        or Path(manifest.get("input_snapshot", "")).resolve() != output / "inputs"
    ):
        raise BlueError("Blue preview changed; its evidence was left in place.")
    digest = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    snapshot = output / "inputs"
    if digest != scope_sha256 or inventory(snapshot) != files:
        raise BlueError("Blue preview changed; its evidence was left in place.")
    events = output / "blue-events.jsonl"
    recorded = [json.loads(line) for line in events.read_text(encoding="utf-8").splitlines()]
    if len(recorded) != 1 or recorded[0].get("kind") != "prepared":
        raise BlueError("Blue preview has additional events; its evidence was left in place.")
    expected_files = {manifest_path, events} | {snapshot / entry["path"] for entry in files}
    expected_dirs = {output, snapshot}
    for file in expected_files:
        expected_dirs.update(
            parent for parent in file.parents if parent == output or output in parent.parents
        )
    actual = list(output.rglob("*"))
    if any(path.is_symlink() or path.is_junction() for path in actual):
        raise BlueError("Blue preview contains a link; its evidence was left in place.")
    if {path for path in actual if path.is_file()} != expected_files or {
        path for path in actual if path.is_dir()
    } != expected_dirs - {output}:
        raise BlueError("Blue preview has additional files; its evidence was left in place.")
    for path in expected_files:
        path.unlink()
    for path in sorted(expected_dirs, key=lambda item: len(item.parts), reverse=True):
        path.rmdir()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strix blue",
        description=(
            "Operator-led audits of authorized local software. "
            "Run without a subcommand to open the Blue TUI."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="Hash the target and preview a bounded run")
    prepare.add_argument("target", type=Path, help="Local file or directory you may assess")
    prepare.add_argument(
        "--output", type=Path, help="Fresh directory for the manifest and evidence"
    )
    prepare.add_argument("--case-id", help="Case identifier shared with linked Standard runs")
    prepare.add_argument("--pe-audit", type=Path, help="Hash-pin the RE-LAB PE metadata helper")
    prepare.add_argument(
        "--model", default="gpt-6-sol", help="Codex subscription model with Daybreak Blue access"
    )
    prepare.add_argument("--provider", choices=("codex", "local"), default="codex")
    prepare.add_argument("--endpoint", help="Local OpenAI-compatible /v1 endpoint on a loopback IP")
    prepare.add_argument(
        "--approval",
        choices=("deny", "auto-review"),
        default="deny",
        help="Deny all escalations (default) or allow Codex Auto-review",
    )
    run = sub.add_parser("run", help="Recheck target hashes and start a prepared audit")
    run.add_argument("manifest", type=Path, help="Manifest written by prepare")
    observe = sub.add_parser("observe", help="Observe an approved local PE process")
    observe.add_argument("manifest", type=Path, help="Blue manifest for the target")
    observe.add_argument("--mode", choices=("launch", "attach"), required=True)
    observe.add_argument("--file", type=Path, help="Relative .exe path within a directory target")
    observe.add_argument("--pid", type=int, help="Existing process ID for attach")
    observe.add_argument(
        "--timeout", type=_observation_seconds, default=5.0, help="Observation seconds (0.1 to 30)"
    )
    handoff = sub.add_parser("handoff", help="Stage a reviewed Blue finding for Standard")
    handoff.add_argument("run", nargs="?", help="Blue run name in the shared catalog")
    handoff.add_argument("--finding", action="append", default=[], help="Recorded finding ID")
    handoff.add_argument("--question", action="append", default=[], help="Question for Standard")
    handoff.add_argument("--scope", help="New Standard scope and limits")
    handoff.add_argument(
        "--staged", type=Path, help="Launch a previously reviewed handoff directory"
    )
    handoff.add_argument("--model", help="Local Standard model route")
    handoff.add_argument("--endpoint", help="Loopback OpenAI-compatible /v1 endpoint")
    handoff.add_argument("--launch", action="store_true", help="Launch Standard after review")
    return parser


def _observation_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("observation time must be a number") from exc
    if not math.isfinite(seconds) or not 0.1 <= seconds <= 30:
        raise argparse.ArgumentTypeError("observation time must be between 0.1 and 30 seconds")
    return seconds


def _run_prepared(  # noqa: PLR0912, PLR0915
    manifest_path: Path,
    *,
    confirmed_phrase: str | None = None,
    expected_manifest_sha256: str | None = None,
) -> str:
    manifest_path = manifest_path.absolute()
    manifest_bytes = manifest_path.read_bytes()
    if (
        expected_manifest_sha256 is not None
        and hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256
    ):
        raise BlueError("Blue manifest changed since the scope preview. Prepare a new run.")
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict):
        raise BlueError("Blue manifest must contain an object.")
    if manifest.get("schema") != "strix-blue-local-v1":
        raise BlueError("Unsupported Blue manifest schema.")
    target = Path(manifest["target"]).resolve(strict=True)
    output = Path(manifest["output"]).resolve(strict=True)
    if manifest_path.resolve(strict=True) != output / "manifest.json":
        raise BlueError("Manifest must be in its declared output directory.")
    if manifest.get("status") != "prepared":
        raise BlueError("This manifest has already been run. Prepare a new one.")
    if _contained(output, target) or _contained(target, output):
        raise BlueError("Output overlaps the target.")
    if inventory(target) != manifest["files"]:
        raise BlueError("Target changed since prepare. Prepare a new run.")
    snapshot = Path(manifest["input_snapshot"])
    if (
        snapshot.resolve(strict=True) != output / "inputs"
        or inventory(snapshot) != manifest["files"]
    ):
        raise BlueError("Input snapshot changed since prepare. Prepare a new run.")
    approval = manifest["approval"]
    if approval not in ("deny", "auto-review"):
        raise BlueError("Unsupported approval mode.")
    if manifest["sandbox"] != {"type": "readOnly", "networkAccess": False}:
        raise BlueError("Unsupported sandbox policy.")
    if manifest["provider"] == "local-openai-compatible":
        if approval != "deny":
            raise BlueError("Local runs do not support Codex Auto-review.")
        validate_loopback_endpoint(manifest["endpoint"])
    elif manifest["provider"] != "codex-subscription" or manifest["endpoint"] is not None:
        raise BlueError("Unsupported provider settings.")
    validate_helper_record(manifest)
    print(f"Target: {target}")
    print(
        f"Files: {len(manifest['files'])}; provider: {manifest['provider']}; "
        f"model: {manifest['model']}; approval: {approval}"
    )
    print("Target files are copied into a hash-checked snapshot. Strix scan tools are disabled.")
    if manifest.get("pe_audit"):
        print(
            "PE inspection runs the configured RE-LAB helper executable: "
            f"{manifest['pe_audit']['path']} (SHA-256 {manifest['pe_audit']['sha256']})."
        )
    if approval == "auto-review":
        print(
            "Auto-review may approve Codex escalation requests. "
            "It does not enforce a target path allowlist."
        )
    phrase = f"RUN {manifest['files'][0]['sha256'][:8]}"
    try:
        supplied = (
            input(f"Type {phrase} to start: ").strip()
            if confirmed_phrase is None
            else confirmed_phrase
        )
    except EOFError as exc:
        raise BlueError("Blue run needs an interactive approval.") from exc
    if supplied != phrase:
        raise BlueError("Run cancelled.")
    manifest["status"] = "running"
    _json(manifest_path, manifest)
    _event(output, "run_started", "Blue analysis started")
    count: int | None = None
    try:
        outcome = (run_codex if manifest["provider"] == "codex-subscription" else run_local)(
            manifest, output
        )
        manifest["status"] = outcome
        if outcome == "completed":
            try:
                count = save_findings(output, manifest)
            except (OSError, TypeError, ValueError) as exc:
                manifest["status"] = "failed"
                (output / "findings-validation-error.txt").write_text(str(exc), encoding="utf-8")
                print(f"Blue findings could not be saved: {exc}", file=sys.stderr)
            else:
                _event(output, "findings_recorded", f"{count} validated findings")
    except Exception:
        manifest["status"] = "failed"
        raise
    finally:
        manifest["ended_utc"] = datetime.now(UTC).isoformat()
        _json(manifest_path, manifest)
        _event(output, "run_finished", f"Blue analysis {manifest['status']}")
    if count is not None:
        print(f"Structured findings: {count}. Missing entries stay unreported in the case view.")
    print(f"Run {manifest['status']}. Evidence: {output}")
    return manifest["status"]


def _observe_prepared(args: argparse.Namespace) -> None:  # noqa: PLR0912 - CLI validation flow
    """Run one separately approved observation against a prepared Blue target."""
    from strix.interface.blue_runtime import (  # noqa: PLC0415
        WARNING,
        TargetPermit,
        launch_confirmation_phrase,
        observe_runtime,
    )

    manifest_path = args.manifest.resolve(strict=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise BlueError("Blue manifest must contain an object.")
    output = Path(manifest["output"]).resolve(strict=True)
    if manifest.get("schema") != "strix-blue-local-v1" or manifest_path != output / "manifest.json":
        raise BlueError("Expected a Blue manifest in its declared output directory.")
    if manifest.get("status") != "completed":
        raise BlueError("Runtime observation requires a completed Blue run.")
    snapshot = output / "inputs"
    if Path(manifest["input_snapshot"]).resolve(strict=True) != snapshot:
        raise BlueError("Blue snapshot path changed.")
    files = manifest.get("files")
    if not isinstance(files, list) or inventory(snapshot) != files:
        raise BlueError("Blue snapshot changed since preparation.")
    relative = args.file
    if relative is None and len(files) == 1:
        relative = Path(files[0]["path"])
    if relative is None or relative.is_absolute() or ".." in relative.parts:
        raise BlueError("Select a relative --file within the Blue snapshot.")
    entry = next((item for item in files if Path(item["path"]) == relative), None)
    if entry is None:
        raise BlueError("Selected file is not in the Blue manifest.")
    selected = snapshot / relative
    if args.mode == "launch" and args.pid is not None:
        raise BlueError("--pid is only valid with --mode attach.")
    if args.mode == "attach" and (args.pid is None or args.pid <= 0):
        raise BlueError("Attach requires a positive --pid.")

    evidence = output / f"runtime-{datetime.now(UTC):%Y%m%d-%H%M%S}-{secrets.token_hex(4)}.jsonl"
    permit = TargetPermit(
        scope_root=snapshot,
        target=selected,
        sha256=entry["sha256"],
        allow_launch=args.mode == "launch",
        allow_attach=args.mode == "attach",
    )
    phrase = (
        launch_confirmation_phrase(permit, evidence, args.timeout)
        if args.mode == "launch"
        else f"ATTACH {args.pid} {entry['sha256'][:8]}"
    )
    print(f"Target: {selected}\nSHA-256 at path: {entry['sha256']}\nEvidence: {evidence}")
    print(WARNING)
    try:
        supplied = input(f"Type {phrase} to approve this {args.mode}: ").strip()
    except EOFError as exc:
        raise BlueError("Runtime observation needs an interactive approval.") from exc
    if supplied != phrase:
        raise BlueError("Runtime observation cancelled.")
    try:
        result = observe_runtime(
            permit,
            mode=args.mode,
            evidence_path=evidence,
            timeout_seconds=args.timeout,
            pid=args.pid,
            confirmation_phrase=phrase if args.mode == "launch" else None,
            risk_acknowledged=True,
        )
    except Exception:
        if evidence.exists():
            _event(
                output,
                "runtimeObservationFailed",
                f"{args.mode} failed; evidence: {evidence.name}",
            )
        raise
    _event(
        output,
        "runtimeObservation",
        f"{args.mode} PID {result.pid}: {result.status}; evidence: {evidence.name}",
    )
    print(f"Runtime observation {result.status}. Evidence: {evidence}")


def run_blue(argv: list[str]) -> int:  # noqa: PLR0911 - Distinct CLI exit states.
    if not argv:
        if not terminal_attached():
            print(
                "Blue's interactive workspace needs a terminal. "
                "Use 'strix blue prepare PATH' for a command-line audit.",
                file=sys.stderr,
            )
            return 2
        args = parse_arguments([])
        args.blue_mode = True
        try:
            asyncio.run(run_tui(args))
        except KeyboardInterrupt:
            return 130
        except RuntimeError as exc:
            print(f"Blue workspace stopped: {exc}", file=sys.stderr)
            return 2
        return 0
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            output = (
                args.output
                or runs_base_dir() / f"blue-{datetime.now(UTC):%Y%m%d-%H%M%S}-{os.getpid()}"
            )
            manifest = prepare_blue(
                args.target,
                output,
                args.model,
                args.approval,
                args.provider,
                args.endpoint,
                args.case_id,
                args.pe_audit,
            )
            path = output / "manifest.json"
            print(json.dumps(manifest, indent=2, ensure_ascii=False))
            print(f'\nRun when ready: strix blue run "{path.absolute()}"')
        elif args.command == "run":
            return 0 if _run_prepared(args.manifest) == "completed" else 1
        elif args.command == "observe":
            _observe_prepared(args)
        else:
            from strix.interface.blue_handoff import run_handoff  # noqa: PLC0415

            run_handoff(args)
    except (
        BlueError,
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"Blue run stopped: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(run_blue(sys.argv[1:]))
