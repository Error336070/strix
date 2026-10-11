"""Read-only case catalog over independent Strix run directories."""

from __future__ import annotations

import json
import os
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.core.paths import runs_base_dir


_CATALOG_FILE = "catalog-roots.json"


@dataclass(frozen=True)
class CaseRun:
    run_id: str
    path: Path
    case_id: str
    mode: str
    parent_run_id: str | None
    finding_refs: tuple[str, ...]
    status: str
    started_at: str
    target: str
    findings: int

    def public(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "mode": self.mode,
            "parent_run_id": self.parent_run_id,
            "finding_refs": list(self.finding_refs),
            "status": self.status,
            "started_at": self.started_at,
            "target": self.target,
            "findings": self.findings,
        }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def catalog_roots(primary: Path | None = None) -> list[Path]:
    """Return configured roots without moving or changing any run."""
    base = (primary or runs_base_dir()).resolve()
    entries = _read_json(base / _CATALOG_FILE).get("roots", [])
    roots = [base]
    if isinstance(entries, list):
        for value in entries:
            if isinstance(value, str):
                candidate = Path(value).expanduser()
                if candidate.is_absolute() and candidate.is_dir():
                    resolved = candidate.resolve()
                    if resolved not in roots:
                        roots.append(resolved)
    return roots


def add_catalog_root(path: Path, primary: Path | None = None) -> Path:
    """Register an existing run directory or a directory containing runs."""
    base = (primary or runs_base_dir()).resolve()
    candidate = path.expanduser().resolve(strict=True)
    if not candidate.is_dir():
        raise ValueError("Run history path must be a directory.")
    if (candidate / "run.json").is_file() or (candidate / "manifest.json").is_file():
        candidate = candidate.parent
    if candidate == base:
        return candidate
    roots = catalog_roots(base)
    if candidate in roots:
        return candidate
    base.mkdir(parents=True, exist_ok=True)
    payload = {"schema": 1, "roots": [str(root) for root in [*roots[1:], candidate]]}
    temporary = base / f".{_CATALOG_FILE}.{os.getpid()}.tmp"
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temporary.replace(base / _CATALOG_FILE)
    return candidate


def _first_target(record: dict[str, Any]) -> str:
    targets = record.get("targets_info", [])
    if isinstance(targets, list):
        for target in targets:
            if isinstance(target, dict) and isinstance(target.get("original"), str):
                return str(target["original"])
    return str(record.get("target") or "")


def _read_run(path: Path) -> CaseRun | None:
    record_path = path / "run.json"
    legacy_blue = not record_path.is_file() and (path / "manifest.json").is_file()
    if not record_path.is_file() and not legacy_blue:
        return None
    record = _read_json(path / ("manifest.json" if legacy_blue else "run.json"))
    if not record:
        return None
    # Directory names are the stable viewer selector. A run.json run_id may be
    # an unrelated UUID, and two registered roots may contain the same name.
    run_id = path.name
    mode = "blue" if legacy_blue else str(record.get("mode") or "standard")
    if mode not in {"blue", "standard"}:
        return None
    case_id = str(record.get("case_id") or run_id)
    parent = record.get("parent_run_id")
    refs = record.get("finding_refs")
    findings_path = path / "vulnerabilities.json"
    try:
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        count = len(findings) if isinstance(findings, list) else 0
    except (OSError, ValueError):
        count = 0
    started = str(record.get("start_time") or record.get("created_utc") or "")
    return CaseRun(
        run_id=run_id,
        path=path,
        case_id=case_id,
        mode=mode,
        parent_run_id=str(parent) if isinstance(parent, str) and parent else None,
        finding_refs=tuple(item for item in refs if isinstance(item, str))
        if isinstance(refs, list)
        else (),
        status=str(record.get("status") or "unknown"),
        started_at=started,
        target=_first_target(record),
        findings=count,
    )


def list_case_runs(primary: Path | None = None) -> list[CaseRun]:
    """List all registered runs; duplicate IDs in different roots are kept separate."""
    runs: list[CaseRun] = []
    for root in catalog_roots(primary):
        try:
            children = root.iterdir()
            for child in children:
                if child.is_dir() and not child.is_symlink():
                    run = _read_run(child)
                    if run is not None:
                        runs.append(run)
        except OSError:
            continue
    return sorted(runs, key=lambda run: (run.started_at, run.run_id), reverse=True)


def resolve_case_run(run_id: str, primary: Path | None = None) -> CaseRun | None:
    if not run_id or any(char in run_id for char in ("/", "\\", "..")):
        return None
    matches = [run for run in list_case_runs(primary) if run.run_id == run_id]
    return matches[0] if len(matches) == 1 else None


def list_case_handoffs(case_id: str, primary: Path | None = None) -> list[dict[str, Any]]:
    """List recorded handoff metadata for a case without opening staged targets."""
    handoffs: list[dict[str, Any]] = []
    for root in catalog_roots(primary):
        directory = root / "handoffs"
        try:
            stages = directory.iterdir()
            for stage in stages:
                if not stage.is_dir() or stage.is_symlink():
                    continue
                record = _read_json(stage / "handoff.json")
                if (
                    record.get("schema") != "strix-reviewed-handoff-v1"
                    or record.get("case_id") != case_id
                    or not isinstance(record.get("parent_run_id"), str)
                ):
                    continue
                refs = record.get("finding_refs")
                files = record.get("files")
                questions = record.get("questions")
                if not isinstance(refs, list) or not isinstance(files, list):
                    continue
                handoffs.append(
                    {
                        "id": stage.name,
                        "parent_run_id": record["parent_run_id"],
                        "finding_refs": [ref for ref in refs if isinstance(ref, str)],
                        "scope": record.get("scope")
                        if isinstance(record.get("scope"), str)
                        else "",
                        "questions": [item for item in questions if isinstance(item, str)]
                        if isinstance(questions, list)
                        else [],
                        "files": [
                            {"path": item["path"], "sha256": item["sha256"]}
                            for item in files
                            if isinstance(item, dict)
                            and isinstance(item.get("path"), str)
                            and isinstance(item.get("sha256"), str)
                        ],
                        "launch_ready": record.get("launch_ready") is True,
                        "created_at": record.get("created_utc")
                        if isinstance(record.get("created_utc"), str)
                        else "",
                    }
                )
        except OSError:
            continue
    return sorted(handoffs, key=lambda item: (item["created_at"], item["id"]), reverse=True)


def case_finding_locations(run: CaseRun, finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Join recorded finding locations to hashes in the same run's Blue manifest."""
    manifest = _read_json(run.path / "manifest.json") if run.mode == "blue" else {}
    files = manifest.get("files")
    hashes = (
        {
            item["path"]: item["sha256"]
            for item in files
            if isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and isinstance(item.get("sha256"), str)
        }
        if isinstance(files, list)
        else {}
    )
    locations = finding.get("code_locations")
    result: list[dict[str, Any]] = []
    if isinstance(locations, list):
        for location in locations:
            if not isinstance(location, dict) or not isinstance(location.get("file"), str):
                continue
            path = location["file"]
            line = location.get("start_line")
            result.append(
                {
                    "path": path,
                    "line": line
                    if isinstance(line, int) and not isinstance(line, bool) and line > 0
                    else None,
                    "sha256": hashes.get(path),
                }
            )
    if not result:
        path = finding.get("code_file") or finding.get("target")
        if isinstance(path, str) and path:
            result.append({"path": path, "line": None, "sha256": hashes.get(path)})
    return result


def event_time(value: Any, fallback: str = "") -> str:
    if isinstance(value, int | float) and value > 0:
        return datetime.fromtimestamp(value / 1000, UTC).isoformat()
    if isinstance(value, str) and value:
        return value
    return fallback


def case_timeline(  # noqa: PLR0912, PLR0915
    case_id: str, primary: Path | None = None, limit: int = 500
) -> list[dict[str, str]]:
    """Merge bounded, per-run events for display; never write a shared event log."""
    from strix.interface.viewer.transcript import build_run_state  # noqa: PLC0415

    events: list[dict[str, str]] = []
    for run in list_case_runs(primary):
        if run.case_id != case_id:
            continue
        if run.mode == "blue":
            activity_log = run.path / "blue-events.jsonl"
            try:
                with activity_log.open(encoding="utf-8") as source:
                    activity_lines = list(deque(enumerate(source, 1), maxlen=limit))
            except OSError:
                activity_lines = []
            for number, line in activity_lines:
                try:
                    activity = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(activity, dict):
                    continue
                events.append(
                    {
                        "id": f"{run.run_id}:activity:{number}",
                        "run_id": run.run_id,
                        "mode": "blue",
                        "timestamp": event_time(activity.get("timestamp"), run.started_at),
                        "kind": str(activity.get("kind") or "activity"),
                        "summary": str(activity.get("summary") or "Blue activity"),
                    }
                )
            log = run.path / "codex-events.jsonl"
            try:
                with log.open(encoding="utf-8") as source:
                    lines = list(deque(enumerate(source, 1), maxlen=limit))
            except OSError:
                lines = []
            for number, line in lines:
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(raw, dict):
                    continue
                method = raw.get("method")
                if not isinstance(method, str) or not method.startswith(("item/", "turn/")):
                    continue
                params = raw.get("params")
                item = params.get("item") if isinstance(params, dict) else None
                item_type = item.get("type") if isinstance(item, dict) else None
                if method.endswith("/delta") or item_type == "reasoning":
                    continue
                if method.startswith("item/") and method not in {
                    "item/started", "item/completed", "item/tool/call"
                }:
                    continue
                events.append(
                    {
                        "id": f"{run.run_id}:blue:{number}",
                        "run_id": run.run_id,
                        "mode": "blue",
                        "timestamp": event_time(raw.get("emittedAtMs"), run.started_at),
                        "kind": method,
                        "summary": str(item_type or method),
                    }
                )
        else:
            try:
                standard_events = build_run_state(run.path)["events"][-limit:]
            except (OSError, ValueError, KeyError):
                standard_events = []
            for index, raw in enumerate(standard_events):
                if not isinstance(raw, dict):
                    continue
                kind = str(raw.get("type") or "event")
                data = raw.get("data")
                event = {
                    "id": f"{run.run_id}:standard:{raw.get('id', index)}",
                    "run_id": run.run_id,
                    "mode": "standard",
                    "timestamp": event_time(raw.get("timestamp"), run.started_at),
                    "kind": kind,
                    "summary": str(data.get("tool_name") if isinstance(data, dict) else kind),
                }
                if isinstance(data, dict) and isinstance(data.get("finding_id"), str):
                    event["finding_id"] = data["finding_id"]
                events.append(event)
    events.sort(key=lambda item: (item["timestamp"], item["id"]))
    return events[-limit:]
