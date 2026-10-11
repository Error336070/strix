"""Explicit, hash-backed Blue to Standard handoff without sharing model state."""

# ruff: noqa: T201 - This module presents an interactive operator review.

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from strix.core.paths import runs_base_dir
from strix.interface.blue import BlueError, inventory
from strix.interface.blue_local import validate_loopback_endpoint
from strix.report.cases import resolve_case_run


if TYPE_CHECKING:
    import argparse

    from strix.report.cases import CaseRun


def _copy_verified_snapshot(
    snapshot: Path, target: Path, files: list[dict[str, object]]
) -> None:
    # Preserve unexpected links as links, so inventory rejects them rather
    # than dereferencing an out-of-scope file during staging.
    shutil.copytree(snapshot, target, symlinks=True)
    if inventory(target) != files:
        raise BlueError("Staged target differs from Blue evidence.")


def _review_blue_selection(
    run_name: str,
    finding_ids: list[str],
    questions: list[str],
    scope: str,
    model: str | None,
    endpoint: str | None,
) -> tuple[CaseRun, dict[str, Any], Path, list[dict[str, Any]], dict[str, object]]:
    source = resolve_case_run(run_name)
    if source is None or source.mode != "blue":
        raise BlueError("Select a unique Blue run in the registered catalog.")
    manifest = json.loads((source.path / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "completed":
        raise BlueError("Handoff requires a completed Blue run.")
    snapshot = source.path / "inputs"
    if snapshot.resolve(strict=True) != Path(manifest["input_snapshot"]).resolve(strict=True):
        raise BlueError("Blue input snapshot moved.")
    if inventory(snapshot) != manifest["files"]:
        raise BlueError("Blue snapshot no longer matches its evidence hashes.")
    recorded = json.loads((source.path / "vulnerabilities.json").read_text(encoding="utf-8"))
    if not isinstance(recorded, list):
        raise BlueError("Blue findings artifact must be a list.")
    findings = []
    for finding_id in dict.fromkeys(finding_ids):
        matches = [
            item for item in recorded if isinstance(item, dict) and item.get("id") == finding_id
        ]
        if len(matches) != 1:
            raise BlueError(f"Finding {finding_id!r} is missing or ambiguous.")
        findings.append(matches[0])
    if not findings or not scope.strip():
        raise BlueError("At least one finding and the new Standard scope are required.")
    if endpoint is not None:
        validate_loopback_endpoint(endpoint)
    if model is not None and (not model.startswith("openai/") or len(model) <= len("openai/")):
        raise BlueError("Standard's local OpenAI-compatible model must use openai/MODEL.")
    preview: dict[str, object] = {
        "case_id": source.case_id,
        "parent_run_id": source.selector,
        "parent_run_name": source.run_id,
        "blue_run": str(source.path),
        "files": manifest["files"],
        "findings": findings,
        "finding_refs": [item["id"] for item in findings],
        "questions": questions,
        "scope": scope,
        "standard_model": model,
        "standard_endpoint": endpoint,
    }
    preview["preview_sha256"] = hashlib.sha256(
        json.dumps(preview, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    ).hexdigest()
    return source, manifest, snapshot, findings, preview


def preview_handoff(
    run_name: str,
    finding_ids: list[str],
    questions: list[str],
    scope: str,
    model: str | None,
    endpoint: str | None,
) -> dict[str, object]:
    """Review a selected handoff without creating files or launching Standard."""
    return _review_blue_selection(
        run_name, finding_ids, questions, scope, model, endpoint
    )[4]


def stage_handoff(
    run_name: str,
    finding_ids: list[str],
    questions: list[str],
    scope: str,
    model: str | None,
    endpoint: str | None,
    *,
    expected_preview_digest: str | None = None,
) -> tuple[Path, dict[str, object]]:
    """Copy a freshly verified Blue snapshot after optional preview approval."""
    source, manifest, snapshot, findings, preview = _review_blue_selection(
        run_name, finding_ids, questions, scope, model, endpoint
    )
    if expected_preview_digest is not None and preview["preview_sha256"] != expected_preview_digest:
        raise BlueError("Blue evidence or handoff scope changed after preview.")
    base = runs_base_dir().resolve()
    base.mkdir(parents=True, exist_ok=True)
    handoffs = base / "handoffs"
    stage = handoffs / f"handoff-{uuid4().hex[:12]}"
    stage.mkdir(parents=True, exist_ok=False)
    target = stage / "target"
    try:
        _copy_verified_snapshot(snapshot, target, manifest["files"])
        record: dict[str, object] = {
            "schema": "strix-reviewed-handoff-v1",
            "created_utc": datetime.now(UTC).isoformat(),
            "case_id": source.case_id,
            "parent_run_id": source.selector,
            "parent_run_name": source.run_id,
            "blue_run": str(source.path),
            "target": str(target),
            "files": manifest["files"],
            "findings": findings,
            "finding_refs": [item["id"] for item in findings],
            "questions": questions,
            "scope": scope,
            "standard_model": model,
            "standard_endpoint": endpoint,
            "preview_sha256": preview["preview_sha256"],
            "launch_ready": model is not None and endpoint is not None,
            "runtime_observations": "missing unless recorded in Blue evidence",
        }
        (stage / "handoff.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )
    except Exception:
        # This fresh directory is still a direct child of the chosen handoffs
        # root. Do not leave a partial copy looking like a reviewable handoff.
        if stage.parent == handoffs and not stage.is_symlink():
            shutil.rmtree(stage)
        raise
    return stage, record


def _verify_recorded_findings(source_path: Path, record: dict[str, object]) -> None:
    findings = record.get("findings")
    if not isinstance(findings, list) or not findings:
        raise BlueError("The handoff has no selected findings.")
    recorded = json.loads((source_path / "vulnerabilities.json").read_text(encoding="utf-8"))
    if not isinstance(recorded, list):
        raise BlueError("The linked Blue findings are unavailable.")
    for finding in findings:
        if not isinstance(finding, dict) or sum(item == finding for item in recorded) != 1:
            raise BlueError("A staged finding differs from the linked Blue evidence.")
    refs = [item.get("id") for item in findings]
    if not all(isinstance(ref, str) and ref for ref in refs) or record.get("finding_refs") != refs:
        raise BlueError("Staged finding references changed.")


def load_staged_handoff(stage: Path) -> dict[str, object]:
    """Recheck a saved handoff before a separate, later launch."""
    if stage.is_symlink():
        raise BlueError("Staged handoff must not be a symlink.")
    stage = stage.resolve(strict=True)
    handoffs = (runs_base_dir().resolve() / "handoffs").resolve(strict=True)
    if stage.parent != handoffs or stage.is_symlink():
        raise BlueError("Staged handoff must be a direct child of the shared handoffs directory.")
    record_path = stage / "handoff.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if not isinstance(record, dict) or record.get("schema") != "strix-reviewed-handoff-v1":
        raise BlueError("Unsupported staged handoff.")
    target = stage / "target"
    if target.resolve(strict=True) != Path(str(record.get("target"))).resolve(strict=True):
        raise BlueError("Staged target path differs from the reviewed handoff.")
    if inventory(target) != record.get("files"):
        raise BlueError("Staged target differs from the reviewed evidence hashes.")
    source = resolve_case_run(str(record.get("parent_run_id") or ""))
    if source is None or source.mode != "blue" or source.case_id != record.get("case_id"):
        raise BlueError("The linked Blue run is unavailable or changed.")
    if str(source.path) != record.get("blue_run"):
        raise BlueError("The linked Blue run path differs from the handoff.")
    source_manifest = json.loads((source.path / "manifest.json").read_text(encoding="utf-8"))
    if source_manifest.get("files") != record["files"]:
        raise BlueError("The linked Blue evidence hashes differ from the handoff.")
    _verify_recorded_findings(source.path, record)
    if not isinstance(record.get("scope"), str) or not record["scope"].strip():
        raise BlueError("The handoff has no scoped instruction.")
    return record


def _standard_command(
    stage: Path, model: str, endpoint: str, expected_hash: str
) -> tuple[list[str], dict[str, str]]:
    """Recheck the exact reviewed record and return Standard's isolated route."""
    if not model.startswith("openai/") or len(model) <= len("openai/"):
        raise BlueError("Standard's local model must use openai/MODEL.")
    validate_loopback_endpoint(endpoint)
    current_hash = hashlib.sha256((stage / "handoff.json").read_bytes()).hexdigest()
    if current_hash != expected_hash:
        raise BlueError("Handoff changed during approval; staged copy retained.")
    record = load_staged_handoff(stage)
    questions = record.get("questions")
    finding_refs = record.get("finding_refs")
    if not isinstance(questions, list) or not isinstance(finding_refs, list):
        raise BlueError("Staged handoff questions or finding references are invalid.")
    instruction = (
        "Investigate only the staged target and within this scope: " + str(record["scope"]) + "\n"
        "Questions: " + "; ".join(str(item) for item in questions) + "\n"
        "Reviewed evidence: " + json.dumps(record["findings"], ensure_ascii=False)
    )
    environment = os.environ.copy()
    environment["STRIX_LLM"] = model
    environment["LLM_API_BASE"] = endpoint
    environment["LLM_API_KEY"] = "local-only"
    environment["STRIX_API_TYPE"] = "chat_completions"
    # -P excludes the working directory; pin imports to the Strix package that
    # created this handoff, even when Standard is launched from a target folder.
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
    environment.pop("OPENAI_API_BASE", None)
    environment.pop("OPENAI_BASE_URL", None)
    command = [
        sys.executable,
        "-P",
        "-c",
        "from strix.interface.main import main; main()",
        "--target",
        str(stage / "target"),
        "--case-id",
        str(record["case_id"]),
        "--parent-run-id",
        str(record["parent_run_id"]),
        *[
            piece
            for finding_id in finding_refs
            for piece in ("--finding-ref", str(finding_id))
        ],
        "--instruction",
        instruction,
    ]
    return command, environment


def launch_staged_handoff(
    stage: Path, model: str, endpoint: str, *, expected_hash: str
) -> int:
    """Launch Standard in its own Windows console after a TUI approval."""
    if os.name != "nt":
        raise BlueError("TUI handoff launch currently requires a Windows console.")
    command, environment = _standard_command(stage, model, endpoint, expected_hash)
    process = subprocess.Popen(  # noqa: S603
        command,
        env=environment,
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    return process.pid


def run_handoff(args: argparse.Namespace) -> None:
    endpoint = getattr(args, "endpoint", None)
    if args.staged is not None:
        if not args.launch or args.run or args.finding or args.scope or args.question:
            raise BlueError("--staged is for launching a saved handoff without new scope edits.")
        stage = args.staged
        record = load_staged_handoff(stage)
        stage = stage.resolve(strict=True)
    else:
        if not args.run or not args.finding or not args.scope:
            raise BlueError("A Blue run, at least one finding, and --scope are required.")
        stage, record = stage_handoff(
            args.run, args.finding, args.question, args.scope, args.model, endpoint
        )
    print(json.dumps(record, indent=2, ensure_ascii=False))
    print(f"Staged copy: {stage}")
    print("Standard may modify its staged copy and use its existing pentesting tools.")
    print("The new scope applies to Standard; Blue approval settings do not transfer.")
    if not args.launch:
        print("Review-only handoff saved. A local Standard model is needed before launch.")
        return
    if not args.model or not endpoint:
        raise BlueError("Standard launch needs --model and --endpoint.")
    print(f"Standard model: {args.model}; endpoint: {endpoint}")
    reviewed_hash = hashlib.sha256((stage / "handoff.json").read_bytes()).hexdigest()
    phrase = f"STANDARD {reviewed_hash[:8]}"
    if input(f"Type {phrase} to launch: ").strip() != phrase:
        raise BlueError("Standard launch cancelled; staged copy retained.")
    command, environment = _standard_command(stage, args.model, endpoint, reviewed_hash)
    subprocess.run(command, env=environment, check=True)  # noqa: S603
