"""Hash-bound, read-only PE metadata inspection through the configured RE-LAB helper."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _local_path(path: Path) -> Path:
    if str(path).startswith(("\\\\", "//")):
        raise ValueError("UNC and device paths are outside the local Blue scope.")
    for component in (path, *path.parents):
        if component.is_symlink() or component.is_junction():
            raise ValueError("Linked and junction paths are outside the local Blue scope.")
    resolved = path.resolve(strict=True)
    if str(resolved).startswith(("\\\\", "//")):
        raise ValueError("UNC and device paths are outside the local Blue scope.")
    return resolved


def trusted_helper_record(tool: Path, target: Path, output: Path) -> dict[str, Any]:
    """Pin an operator-configured local PE helper and its executable bundle."""
    configured = os.environ.get("STRIX_PE_AUDIT_HELPER")
    if not configured:
        raise ValueError("Set STRIX_PE_AUDIT_HELPER to the trusted RE-LAB pe-audit.exe.")
    configured_path = Path(configured)
    if not configured_path.is_absolute():
        raise ValueError("STRIX_PE_AUDIT_HELPER must be an absolute local path.")
    trusted = _local_path(configured_path)
    selected = _local_path(tool)
    target = _local_path(target)
    if not trusted.is_file() or trusted.name.lower() != "pe-audit.exe" or selected != trusted:
        raise ValueError("The PE helper must be the configured RE-LAB pe-audit.exe.")
    if selected == target or (target.is_dir() and target in selected.parents):
        raise ValueError("The PE helper must be outside the audited target.")
    if selected == output or output in selected.parents:
        raise ValueError("The PE helper must be outside the Blue output directory.")
    bundle = []
    for candidate in sorted(selected.parent.iterdir(), key=lambda path: path.name.casefold()):
        if candidate.suffix.lower() not in {".exe", ".dll", ".json"}:
            continue
        item = _local_path(candidate)
        if not item.is_file():
            raise ValueError("The PE helper bundle contains a non-file entry.")
        bundle.append({"name": item.name, "size": item.stat().st_size, "sha256": _digest(item)})
    return {"path": str(selected), "sha256": _digest(selected), "bundle": bundle}


def validate_helper_record(manifest: dict[str, Any]) -> None:
    """Fail closed if the selected helper or its loaded dependencies changed."""
    record = manifest.get("pe_audit")
    if record is None:
        return
    if not isinstance(record, dict) or not isinstance(record.get("path"), str):
        raise TypeError("Blue PE helper record is malformed.")
    current = trusted_helper_record(
        Path(record["path"]), Path(manifest["target"]), Path(manifest["output"])
    )
    if current != record:
        raise ValueError("RE-LAB PE helper or its dependency bundle changed since preparation.")


def inspect_pe(manifest: dict[str, Any], arguments: Any) -> dict[str, Any]:  # noqa: PLR0911
    def denied(reason: str) -> dict[str, Any]:
        return {"success": False, "contentItems": [{"type": "inputText", "text": reason}]}

    if not isinstance(arguments, dict) or not isinstance(arguments.get("path"), str):
        return denied("A scoped file path is required.")
    name = arguments["path"]
    entry = next((item for item in manifest["files"] if item["path"] == name), None)
    if entry is None:
        return denied("Path is outside the prepared target.")
    output = Path(manifest["output"]).resolve(strict=True)
    root = Path(manifest["input_snapshot"])
    if root.is_symlink() or root.is_junction() or root.resolve(strict=True) != output / "inputs":
        return denied("Input snapshot directory changed.")
    target = root / name
    if target.is_symlink() or target.is_junction() or not target.is_file():
        return denied("Target path is no longer a regular file.")
    if root.resolve(strict=True) not in target.resolve(strict=True).parents:
        return denied("Target escaped the snapshot.")
    data = target.read_bytes()
    if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        return denied("Target hash changed.")
    if not data.startswith(b"MZ"):
        return denied("Target is not a Windows PE candidate.")
    tool_record = manifest.get("pe_audit")
    if not isinstance(tool_record, dict):
        return denied("No RE-LAB PE helper was configured for this run.")
    try:
        validate_helper_record(manifest)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return denied(f"RE-LAB PE helper is unavailable: {exc}")
    tool = Path(tool_record["path"])
    try:
        result = subprocess.run(  # noqa: S603
            [str(tool), str(target)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return denied(f"PE helper failed: {exc}")
    text = (result.stdout + "\n" + result.stderr)[:24000]
    if result.returncode not in {0, 1}:
        return denied(f"PE helper exited {result.returncode}: {text}")
    return {"success": True, "contentItems": [{"type": "inputText", "text": text}]}
