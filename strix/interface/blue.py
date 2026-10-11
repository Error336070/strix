"""Operator-led, local-only Blue audits. This module bypasses Strix scan tools."""

# ruff: noqa: T201 - This module is an interactive CLI.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.interface.blue_codex import run_codex
from strix.interface.blue_local import run_local, validate_loopback_endpoint


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
) -> dict[str, Any]:
    target = target.resolve(strict=True)
    output = output.parent.resolve(strict=True) / output.name
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
    manifest: dict[str, Any] = {
        "schema": "strix-blue-local-v1",
        "created_utc": datetime.now(UTC).isoformat(),
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
        data = destination.read_bytes()
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BlueError(f"Blue v1 supports UTF-8 text only: {entry['path']}") from exc
        if b"\x00" in data:
            raise BlueError(f"Blue v1 supports UTF-8 text only: {entry['path']}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strix blue", description="Operator-led audits of authorized local software"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="Hash the target and preview a bounded run")
    prepare.add_argument("target", type=Path, help="Local file or directory you may assess")
    prepare.add_argument(
        "--output", type=Path, required=True, help="Fresh directory for the manifest and evidence"
    )
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
    return parser


def _run_prepared(manifest_path: Path) -> None:  # noqa: PLR0912
    manifest_path = manifest_path.absolute()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
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
    print(f"Target: {target}")
    print(
        f"Files: {len(manifest['files'])}; provider: {manifest['provider']}; "
        f"model: {manifest['model']}; approval: {approval}"
    )
    print("Target files are copied into a hash-checked snapshot. Strix scan tools are disabled.")
    if approval == "auto-review":
        print(
            "Auto-review may approve Codex escalation requests. "
            "It does not enforce a target path allowlist."
        )
    phrase = f"RUN {manifest['files'][0]['sha256'][:8]}"
    if input(f"Type {phrase} to start: ").strip() != phrase:
        raise BlueError("Run cancelled.")
    manifest["status"] = "running"
    _json(manifest_path, manifest)
    try:
        outcome = (run_codex if manifest["provider"] == "codex-subscription" else run_local)(
            manifest, output
        )
        manifest["status"] = outcome
    except Exception:
        manifest["status"] = "failed"
        raise
    finally:
        _json(manifest_path, manifest)
    print(f"Run {manifest['status']}. Evidence: {output}")


def run_blue(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            manifest = build_manifest(
                args.target,
                args.output,
                args.model,
                args.approval,
                args.provider,
                args.endpoint,
            )
            args.output.mkdir(parents=True, exist_ok=False)
            _copy_snapshot(manifest)
            path = args.output / "manifest.json"
            _json(path, manifest)
            print(json.dumps(manifest, indent=2, ensure_ascii=False))
            print(f'\nRun when ready: strix blue run "{path.absolute()}"')
        else:
            _run_prepared(args.manifest)
    except (BlueError, OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Blue run stopped: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(run_blue(sys.argv[1:]))
