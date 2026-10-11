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
from uuid import uuid4

from strix.core.paths import runs_base_dir
from strix.interface.blue import BlueError, inventory
from strix.interface.blue_local import validate_loopback_endpoint
from strix.report.cases import resolve_case_run


def stage_handoff(
    run_name: str,
    finding_ids: list[str],
    questions: list[str],
    scope: str,
    model: str | None,
    endpoint: str | None,
) -> tuple[Path, dict[str, object]]:
    """Copy a verified Blue snapshot and only the selected recorded findings."""
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
    base = runs_base_dir().resolve()
    base.mkdir(parents=True, exist_ok=True)
    stage = base / "handoffs" / f"handoff-{uuid4().hex[:12]}"
    stage.mkdir(parents=True, exist_ok=False)
    target = stage / "target"
    shutil.copytree(snapshot, target, symlinks=False)
    if inventory(target) != manifest["files"]:
        raise BlueError("Staged target differs from Blue evidence.")
    record: dict[str, object] = {
        "schema": "strix-reviewed-handoff-v1",
        "created_utc": datetime.now(UTC).isoformat(),
        "case_id": source.case_id,
        "parent_run_id": source.run_id,
        "blue_run": str(source.path),
        "target": str(target),
        "files": manifest["files"],
        "findings": findings,
        "finding_refs": [item["id"] for item in findings],
        "questions": questions,
        "scope": scope,
        "standard_model": model,
        "standard_endpoint": endpoint,
        "launch_ready": model is not None and endpoint is not None,
        "runtime_observations": "missing unless recorded in Blue evidence",
    }
    (stage / "handoff.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
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


def run_handoff(args: object) -> None:
    endpoint = getattr(args, "endpoint", None)
    if args.staged is not None:
        if not args.launch or args.run or args.finding or args.scope or args.question:
            raise BlueError("--staged is for launching a saved handoff without new scope edits.")
        stage = args.staged.resolve(strict=True)
        record = load_staged_handoff(stage)
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
    if not args.model.startswith("openai/") or len(args.model) <= len("openai/"):
        raise BlueError("Standard's local model must use openai/MODEL.")
    validate_loopback_endpoint(endpoint)
    print(f"Standard model: {args.model}; endpoint: {endpoint}")
    reviewed_hash = hashlib.sha256((stage / "handoff.json").read_bytes()).hexdigest()
    phrase = f"STANDARD {reviewed_hash[:8]}"
    if input(f"Type {phrase} to launch: ").strip() != phrase:
        raise BlueError("Standard launch cancelled; staged copy retained.")
    if hashlib.sha256((stage / "handoff.json").read_bytes()).hexdigest() != reviewed_hash:
        raise BlueError("Handoff changed during approval; staged copy retained.")
    record = load_staged_handoff(stage)
    instruction = (
        "Investigate only the staged target and within this scope: " + str(record["scope"]) + "\n"
        "Questions: " + "; ".join(str(item) for item in record["questions"]) + "\n"
        "Reviewed evidence: " + json.dumps(record["findings"], ensure_ascii=False)
    )
    environment = os.environ.copy()
    environment["STRIX_LLM"] = args.model
    environment["LLM_API_BASE"] = endpoint
    environment["LLM_API_KEY"] = "local-only"
    environment["STRIX_API_TYPE"] = "chat_completions"
    environment.pop("OPENAI_API_BASE", None)
    environment.pop("OPENAI_BASE_URL", None)
    command = [
        sys.executable,
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
            for finding_id in record["finding_refs"]
            for piece in ("--finding-ref", str(finding_id))
        ],
        "--instruction",
        instruction,
    ]
    subprocess.run(command, env=environment, check=True)  # noqa: S603
