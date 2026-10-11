"""Build the JSON payloads the viewer SPA consumes from a run directory."""

from __future__ import annotations

import json
import logging
from collections import deque
from typing import TYPE_CHECKING, Any

from strix.core.paths import run_record_path
from strix.interface.tui.live_view import TuiLiveView
from strix.report.cases import event_time


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_TERMINAL_STATUSES = {"completed", "stopped", "failed", "interrupted"}

_KNOWN_SEVERITIES = ("critical", "high", "medium", "low")


def severity_counts(vulns: list[Any]) -> dict[str, int]:
    """Bucket vulnerabilities into critical/high/medium/low counts.

    Mirrors the SPA's ``severityCounts``: severities are lowercased and
    trimmed, and anything outside the four known buckets (``info``,
    ``informational``, ``unknown``, missing, ...) folds into ``low`` so the
    shared UI renders cleanly.
    """
    counts = dict.fromkeys(_KNOWN_SEVERITIES, 0)
    for vuln in vulns:
        raw = vuln.get("severity") if isinstance(vuln, dict) else None
        severity = str(raw or "").lower().strip()
        if severity not in counts:
            severity = "low"
        counts[severity] += 1
    return counts


def build_run_state(run_dir: Path) -> dict[str, Any]:
    """Agent graph + full per-agent event/message stream.

    Reuses the shared ``TuiLiveView`` projection so the viewer and the TUI
    share one parser for ``agents.json`` + ``agents.db`` and never drift.
    """
    if not (run_dir / "agents.json").exists() and (run_dir / "manifest.json").exists():
        return _blue_transcript(run_dir)
    view = TuiLiveView()
    view.hydrate_from_run_dir(run_dir)
    return {"agents": list(view.agents.values()), "events": view.events}


def read_run_summary(run_dir: Path) -> dict[str, Any]:
    """The ``run.json`` record plus a computed ``finished`` flag."""
    record = _load_json(run_record_path(run_dir), default={})
    if not record and (run_dir / "manifest.json").is_file():
        manifest = _load_json(run_dir / "manifest.json", default={})
        if isinstance(manifest, dict):
            record = {
                "run_id": run_dir.name,
                "run_name": run_dir.name,
                "mode": "blue",
                "case_id": manifest.get("case_id") or run_dir.name,
                "parent_run_id": manifest.get("parent_run_id"),
                "start_time": manifest.get("created_utc"),
                "end_time": manifest.get("ended_utc"),
                "status": manifest.get("status"),
                "targets_info": [{"original": manifest.get("target")}],
            }
    if not isinstance(record, dict):
        record = {}
    status = record.get("status")
    finished = status in _TERMINAL_STATUSES and (
        bool(record.get("end_time")) or (run_dir / "manifest.json").is_file()
    )
    return {**record, "finished": finished}


def primary_target(record: dict[str, Any]) -> str | None:
    """The first target's original string from a run record, or None."""
    targets = record.get("targets_info")
    if isinstance(targets, list):
        for entry in targets:
            if isinstance(entry, dict):
                original = entry.get("original")
                if isinstance(original, str) and original:
                    return original
    return None


def read_vulnerabilities(run_dir: Path) -> list[Any]:
    """The ``vulnerabilities.json`` list (empty until a scan writes it)."""
    data = _load_json(run_dir / "vulnerabilities.json", default=[])
    return data if isinstance(data, list) else []


def read_report_markdown(run_dir: Path) -> str:
    """The executive report markdown (empty until a scan writes it)."""
    report_path = run_dir / "penetration_test_report.md"
    if not report_path.is_file() and (run_dir / "manifest.json").is_file():
        report_path = run_dir / "report.md"
    try:
        return report_path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _blue_transcript(run_dir: Path) -> dict[str, Any]:
    """Project a Blue app-server trace into the viewer's existing transcript."""
    events: list[dict[str, Any]] = []
    log_path = run_dir / "codex-events.jsonl"
    try:
        with log_path.open(encoding="utf-8") as source:
            lines = list(deque(source, maxlen=1000))
    except OSError:
        lines = []
    for number, line in enumerate(lines):
        try:
            raw = json.loads(line)
        except ValueError:
            continue
        if not isinstance(raw, dict):
            continue
        method = raw.get("method")
        if method not in {"item/started", "item/completed"}:
            continue
        params = raw.get("params")
        item = params.get("item") if isinstance(params, dict) else None
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind not in {"agentMessage", "dynamicToolCall"}:
            continue
        data = (
            {"tool_name": item.get("name") or "read_scope_file", "status": "completed"}
            if kind == "dynamicToolCall"
            else {"content": item.get("text") or ""}
        )
        events.append(
            {
                "id": f"blue-{number}",
                "type": "tool" if kind == "dynamicToolCall" else "chat",
                "agent_id": "blue-codex",
                "timestamp": event_time(raw.get("emittedAtMs")),
                "version": 1,
                "data": data,
            }
        )
    return {
        "agents": [
            {
                "id": "blue-codex",
                "name": "Blue audit",
                "parent_id": None,
                "status": read_run_summary(run_dir).get("status") or "unknown",
                "created_at": "",
                "updated_at": "",
            }
        ],
        "events": events,
    }


def _load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


__all__ = [
    "build_run_state",
    "primary_target",
    "read_report_markdown",
    "read_run_summary",
    "read_vulnerabilities",
    "severity_counts",
]
