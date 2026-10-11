"""Validate optional structured findings in a Blue report against saved evidence."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


_BLOCK = re.compile(r"<strix-findings-json>\s*(\[.*?\])\s*</strix-findings-json>", re.S)


def extract_findings(report: str, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    match = _BLOCK.search(report)
    if not match:
        return []
    value = json.loads(match.group(1))
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("Structured findings must be a list of at most 100 items.")
    files = {item["path"]: item for item in manifest["files"]}
    findings: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, raw in enumerate(value, 1):
        if not isinstance(raw, dict):
            raise TypeError("Structured finding is not an object.")
        identifier = raw.get("id")
        title = raw.get("title")
        description = raw.get("description")
        path = raw.get("path")
        line = raw.get("line")
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier)
            or identifier in ids
            or not isinstance(title, str)
            or not title.strip()
            or not isinstance(description, str)
            or not description.strip()
            or not isinstance(path, str)
            or path not in files
            or not isinstance(line, int)
            or line < 0
        ):
            raise ValueError(f"Finding #{index} lacks a unique ID or scoped evidence location.")
        severity = raw.get("severity")
        if severity not in {"critical", "high", "medium", "low"}:
            raise ValueError(f"Finding #{index} has invalid severity.")
        ids.add(identifier)
        data = (Path(manifest["input_snapshot"]) / path).read_bytes()
        if line:
            try:
                line_count = len(data.decode("utf-8").splitlines())
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"Finding #{index} uses a source line in binary evidence."
                ) from exc
            if line > line_count:
                raise ValueError(f"Finding #{index} cites a line outside the saved file.")
        elif not data.startswith(b"MZ"):
            raise ValueError(f"Finding #{index} needs an exact source line.")
        digest = files[path]["sha256"]
        evidence = f"{path}:{line or 'binary'} SHA-256 {digest}"
        note = raw.get("evidence")
        if isinstance(note, str) and note.strip():
            evidence += "\n" + note.strip()
        findings.append(
            {
                "id": identifier,
                "title": title.strip(),
                "description": description.strip(),
                "severity": severity,
                "timestamp": datetime.now(UTC).isoformat(),
                "evidence": evidence,
                "code_locations": [{"file": path, "start_line": line}] if line else [],
                "remediation_steps": raw.get("remediation")
                if isinstance(raw.get("remediation"), str)
                else None,
                "assumptions": raw.get("uncertainty")
                if isinstance(raw.get("uncertainty"), str)
                else "Dynamic validation missing.",
                "source_sha256": digest,
            }
        )
    return findings


def save_findings(output: Path, manifest: dict[str, Any]) -> int:
    report_path = output / "report.md"
    report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    findings = extract_findings(report, manifest)
    (output / "vulnerabilities.json").write_text(
        json.dumps(findings, indent=2) + "\n", encoding="utf-8"
    )
    return len(findings)
