"""Hash-bound, read-only PE metadata inspection through the configured RE-LAB helper."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any


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
    tool = Path(tool_record["path"])
    if not tool.is_file() or hashlib.sha256(tool.read_bytes()).hexdigest() != tool_record["sha256"]:
        return denied("RE-LAB PE helper hash changed.")
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
