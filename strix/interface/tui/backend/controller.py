"""UI-independent state and command controller for interactive Strix clients."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import math
import os
import shutil
import time
import webbrowser
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from strix.config import load_settings
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.tui.backend.projection import (
    MAX_TERMINAL_EVENTS,
    MAX_TERMINAL_VULNERABILITIES,
    SCAN_MODES,
    SCOPE_MODES,
    bounded_state_projection,
    collection_item_projection,
    sanitize_terminal_text,
    terminal_projection,
)
from strix.interface.utils import is_subscription_run


if TYPE_CHECKING:
    import argparse

    from strix.report.state import ReportState


_STOPPABLE_AGENT_STATUSES = frozenset({"running", "waiting", "budget_paused"})

ChangeCallback = Callable[[], None]
StartCallback = Callable[[], Awaitable[None]]
VerifyCallback = Callable[[], Awaitable[None]]
QuitCallback = Callable[[], Awaitable[None]]


class TuiController:
    """Own setup state and expose serializable scan state to any TUI."""

    def __init__(
        self,
        args: argparse.Namespace,
        *,
        live_view: TuiLiveView | None = None,
        coordinator: Any = None,
        report_state: ReportState | None = None,
        on_start: StartCallback | None = None,
        on_verify: VerifyCallback | None = None,
        on_quit: QuitCallback | None = None,
        on_change: ChangeCallback | None = None,
    ) -> None:
        self.args = args
        self.live_view = live_view or TuiLiveView()
        self.coordinator = coordinator
        self.report_state = report_state
        self.scan_loop: asyncio.AbstractEventLoop | None = None
        self.setup_mode = bool(args.needs_setup)
        self.blue_mode = bool(getattr(args, "blue_mode", False))
        self.scan_started = not self.setup_mode
        self._start_in_progress = False
        self.blue_preview: dict[str, Any] | None = None
        self._blue_task: asyncio.Task[None] | None = None
        self.blue_observation: dict[str, Any] | None = None
        self._blue_grant: dict[str, Any] | None = None
        self._blue_observation_permit: Any = None
        self._blue_observation_task: asyncio.Task[None] | None = None
        self.blue_findings: list[dict[str, Any]] = []
        self.blue_handoff: dict[str, Any] | None = None
        self.scan_state = "setup" if self.setup_mode else "running"
        self.targets = [
            str(target["original"])
            for target in args.targets_info
            if isinstance(target, dict) and target.get("original")
        ]
        instruction = args.instruction
        self.instruction = instruction.strip() if isinstance(instruction, str) else ""
        requested_scan_mode = str(args.scan_mode)
        self.scan_mode = requested_scan_mode if requested_scan_mode in SCAN_MODES else "deep"
        raw_budget = args.max_budget_usd
        self.max_budget_usd = (
            float(raw_budget)
            if isinstance(raw_budget, int | float)
            and not isinstance(raw_budget, bool)
            and math.isfinite(float(raw_budget))
            and raw_budget > 0
            else None
        )
        raw_turns = args.max_turns
        self.max_turns = (
            raw_turns
            if isinstance(raw_turns, int) and not isinstance(raw_turns, bool) and raw_turns > 0
            else DEFAULT_MAX_TURNS
        )
        requested_scope = str(args.scope_mode)
        self.scope_mode = requested_scope if requested_scope in SCOPE_MODES else "auto"
        raw_diff_base = args.diff_base
        self.diff_base = raw_diff_base.strip() if isinstance(raw_diff_base, str) else None
        # Host directory mounted for the agent to work in when the scan has no
        # target, set only once the user confirms it. It is a workspace, not a
        # target: it carries no scan scope, and the instruction is the only
        # source of truth for what to do.
        self.workspace_mount: str | None = None
        # A target-less launch enters the live view and asks there before
        # anything is prepared; this holds the directory awaiting that answer.
        self.pending_workspace_mount: str | None = None
        self.messages: list[dict[str, str]] = []
        self._next_message_id = 1
        self.error: str | None = None
        # The run's MCP connection roster (name / tool_count / dead), pushed by
        # the engine via the mcp_status_sink once the connections are established
        # and again each time one dies. Empty for a run with no MCP connections,
        # so the Go sidebar simply omits the panel. Non-secret by construction.
        self.mcp_connections: list[dict[str, Any]] = []
        self.viewer_status = "idle"
        self.viewer_url: str | None = None
        self._viewer_httpd: Any = None
        self._on_start = on_start
        self._on_verify = on_verify
        self._on_quit = on_quit
        self._on_change = on_change

    def set_change_callback(self, callback: ChangeCallback) -> None:
        self._on_change = callback

    def notify_changed(self) -> None:
        if self._on_change is not None:
            self._on_change()

    def set_runtime(
        self,
        *,
        report_state: ReportState | None = None,
        scan_loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if report_state is not None:
            self.report_state = report_state
        if scan_loop is not None:
            self.scan_loop = scan_loop

    def set_mcp_connections(self, roster: list[dict[str, Any]]) -> None:
        """Store the run's MCP connection roster and repaint.

        ``roster`` is the engine's non-secret status snapshot: one entry per
        connection carrying ``name``, ``tool_count``, and ``dead``. Called once
        when the connections are established (all healthy) and again whenever a
        connection dies (the same whole-roster snapshot, with that one now dead)."""
        self.mcp_connections = [
            {
                "name": str(entry.get("name", "")),
                "tool_count": int(entry.get("tool_count", 0) or 0),
                "dead": bool(entry.get("dead", False)),
            }
            for entry in roster
            if isinstance(entry, dict) and entry.get("name")
        ]
        self.notify_changed()

    def fail_preparation(self, detail: str) -> None:
        self.scan_state = "failed"
        self.error = detail
        self.notify_changed()

    def add_message(self, text: str, level: str = "info") -> None:
        self._append_message(text, level)
        self.notify_changed()

    def _append_message(self, text: str, level: str) -> None:
        self.messages.append(
            {
                "id": f"message-{self._next_message_id}",
                "text": sanitize_terminal_text(text),
                "level": sanitize_terminal_text(level),
            }
        )
        self._next_message_id += 1
        self.messages = self.messages[-200:]

    def snapshot(self) -> dict[str, Any]:
        """Return small mutable state; histories are streamed as collections."""
        model = ""
        with contextlib.suppress(Exception):
            model = (load_settings().llm.model or "").strip()
        usage: dict[str, Any] = {}
        if self.report_state is not None:
            usage = dict(self.report_state.get_total_llm_usage())
        subscription = False
        with contextlib.suppress(Exception):
            subscription = is_subscription_run(self.report_state)
        state = {
            "setup_mode": self.setup_mode,
            "blue_mode": self.blue_mode,
            "scan_started": self.scan_started,
            "scan_state": self.scan_state,
            "targets": [
                terminal_projection(target, max_string=128) for target in self.targets[:16]
            ],
            "target_count": len(self.targets),
            "working_dir": str(Path.cwd()),
            "pending_mount": self.pending_workspace_mount or "",
            "instruction": terminal_projection(self.instruction, max_string=2 * 1024),
            "scan_mode": self.scan_mode,
            "max_budget_usd": self.max_budget_usd,
            "max_turns": self.max_turns,
            "scope_mode": self.scope_mode,
            "diff_base": terminal_projection(self.diff_base, max_string=256),
            "model": terminal_projection(model, max_string=256),
            "caido_url": terminal_projection(
                getattr(self.report_state, "caido_url", None), max_string=1024
            ),
            "messages": [
                {
                    "id": str(message.get("id", ""))[:64],
                    "text": terminal_projection(message.get("text", ""), max_string=256),
                    "level": str(message.get("level", "info"))[:32],
                }
                for message in self.messages[-10:]
            ],
            "usage": terminal_projection(usage, max_string=256, max_items=20),
            "subscription": subscription,
            "connections": [
                {
                    "name": terminal_projection(entry["name"], max_string=64),
                    "tool_count": entry["tool_count"],
                    "dead": entry["dead"],
                }
                for entry in self.mcp_connections[:32]
            ],
            "viewer_status": self.viewer_status,
            "viewer_url": terminal_projection(self.viewer_url, max_string=1024),
            "error": terminal_projection(self.error, max_string=2 * 1024),
            "blue_preview": terminal_projection(self.blue_preview, max_string=1024, max_items=20),
            "blue_observation": terminal_projection(
                self.blue_observation, max_string=2048, max_items=20
            ),
            "blue_findings": terminal_projection(
                self.blue_findings[:20], max_string=256, max_items=20
            ),
            "blue_handoff": terminal_projection(
                self.blue_handoff, max_string=4096, max_items=30
            ),
        }
        return bounded_state_projection(state)

    def collection(self, name: str) -> list[dict[str, Any]]:
        """Return one bounded terminal projection with stable item identities."""
        if name == "agents":
            return [
                {
                    key: terminal_projection(agent.get(key), max_string=256, max_items=5)
                    for key in (
                        "id",
                        "name",
                        "parent_id",
                        "status",
                        "error_message",
                        "created_at",
                        "updated_at",
                    )
                    if key in agent
                }
                for agent in self.live_view.agents.values()
            ]
        if name == "events":
            return [collection_item_projection(event) for event in self.live_view.events]
        if name == "vulnerabilities":
            reports = (
                self.report_state.vulnerability_reports if self.report_state is not None else []
            )[-MAX_TERMINAL_VULNERABILITIES:]
            result: list[dict[str, Any]] = []
            for index, report in enumerate(reports):
                projected = collection_item_projection(report)
                report_id = projected.get("id")
                if not isinstance(report_id, str) or not report_id:
                    projected["id"] = f"vulnerability-{index}"
                result.append(projected)
            return result
        raise ValueError(f"Unknown collection: {name}")

    def collection_snapshot(self, name: str) -> tuple[int | None, list[dict[str, Any]]]:
        """Return a collection cursor and complete bounded projection."""
        if name == "events":
            cursor, events = self.live_view.event_snapshot(limit=MAX_TERMINAL_EVENTS)
            return cursor, [collection_item_projection(event) for event in events]
        return None, self.collection(name)

    def collection_changes(
        self,
        name: str,
        cursor: int,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Return event upserts since a monotonic source cursor."""
        if name != "events":
            raise ValueError(f"Collection {name!r} does not expose incremental changes")
        next_cursor, events = self.live_view.event_changes_since(cursor)
        return next_cursor, [
            collection_item_projection(event) for event in events[-MAX_TERMINAL_EVENTS:]
        ]

    async def handle(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "setup.add_target": self._add_target,
            "setup.set_instruction": self._set_instruction,
            "setup.start": self._start,
            "setup.confirm_mount": self._confirm_mount,
            "setup.blue_prepare": self._blue_prepare,
            "setup.blue_confirm": self._blue_confirm,
            "setup.blue_cancel": self._blue_cancel,
            "blue.observe_preview": self._blue_observe_preview,
            "blue.observe_confirm": self._blue_observe_confirm,
            "blue.observe_cancel": self._blue_observe_cancel,
            "blue.handoff_preview": self._blue_handoff_preview,
            "blue.handoff_stage": self._blue_handoff_stage,
            "blue.handoff_launch": self._blue_handoff_launch,
            "blue.handoff_close": self._blue_handoff_close,
            "agent.send_message": self._send_message,
            "agent.stop": self._stop_agent,
            "viewer.open": self._open_viewer,
            "app.quit": self._quit,
        }
        handler = handlers.get(command)
        if handler is None:
            raise ValueError(f"Unknown command: {command}")
        result = await handler(payload)
        self.notify_changed()
        return result

    async def _add_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        target = self._required_string(payload, "target")
        if target not in self.targets:
            self.targets.append(target)
        return {"target": target, "total": len(self.targets)}

    async def _set_instruction(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        instruction = payload.get("instruction", "")
        if not isinstance(instruction, str):
            raise TypeError("instruction must be a string")
        self.instruction = instruction.strip()
        return {"instruction": self.instruction}

    async def _start(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.scan_started or self._start_in_progress:
            raise RuntimeError("Scan is already starting or running")
        if self.blue_preview is not None:
            raise RuntimeError("Confirm or cancel the Blue preview first")
        # Launching with no target mounts the working directory, so it requires
        # the user's explicit confirmation rather than happening silently.
        mount_working_dir = payload.get("mount_working_dir", False)
        if not isinstance(mount_working_dir, bool):
            raise TypeError("mount_working_dir must be a boolean")
        model = (load_settings().llm.model or "").strip()
        if not model:
            raise ValueError("No model configured. Set STRIX_LLM first.")
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        if not self.targets and not mount_working_dir:
            raise ValueError("No target set. Add a target first.")
        # The model check runs while still on the start screen, for a bare
        # prompt as much as for a named target, so a failure lands in the setup
        # log where the user can fix it and retry rather than in a dead run.
        await self._verify_model()
        if not self.targets:
            # Mounting the working directory needs the user's confirmation, and
            # that is asked in the live view. Enter it now and prepare nothing
            # until the answer arrives, so declining leaves no run behind.
            self.pending_workspace_mount = str(Path.cwd())
            self.setup_mode = False
            self.scan_started = True
            self.scan_state = "preparing"
            return {"started": True}
        await self._begin_scan()
        return {"started": True}

    async def _verify_model(self) -> None:
        if self._on_verify is None:
            return
        self._start_in_progress = True
        try:
            await self._on_verify()
        finally:
            self._start_in_progress = False

    async def _begin_scan(self) -> None:
        if self._on_start is None:
            raise RuntimeError("Scan start is unavailable")
        self._start_in_progress = True
        try:
            await self._on_start()
        except Exception as exc:
            if not self.setup_mode:
                # The live view is already up, so the failure has to show there.
                self.fail_preparation(str(exc))
            raise
        finally:
            self._start_in_progress = False
        self.setup_mode = False
        self.scan_started = True
        self.scan_state = "running"

    async def _confirm_mount(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Answer the pending working-directory mount asked for in the live view."""
        mount = self.pending_workspace_mount
        if mount is None:
            raise RuntimeError("No mount confirmation is pending")
        approved = payload.get("approved")
        if not isinstance(approved, bool):
            raise TypeError("approved must be a boolean")
        self.pending_workspace_mount = None
        # Declining skips the mount, it does not abandon the scan. The prompt is
        # the whole of the input either way; the working directory is only an
        # extra the agent may look at, so the run goes ahead without one.
        self.workspace_mount = mount if approved else None
        await self._begin_scan()
        return {"approved": approved}

    async def _blue_prepare(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        if self.blue_preview is not None:
            raise RuntimeError("Confirm or cancel the current Blue preview first")
        if self.targets:
            raise RuntimeError("Clear Standard targets before preparing Blue")
        target = Path(self._required_string(payload, "target"))
        model = self._required_string({"model": payload.get("model", "gpt-6-sol")}, "model")
        provider = self._required_string({"provider": payload.get("provider", "codex")}, "provider")
        approval = self._required_string({"approval": payload.get("approval", "deny")}, "approval")
        case_id = (
            self._required_string(payload, "case_id") if "case_id" in payload else None
        )
        endpoint = (
            self._required_string(payload, "endpoint") if "endpoint" in payload else None
        )
        pe_audit = (
            Path(self._required_string(payload, "pe_audit"))
            if "pe_audit" in payload else None
        )
        if pe_audit is None and os.environ.get("STRIX_PE_AUDIT_HELPER"):
            pe_audit = Path(os.environ["STRIX_PE_AUDIT_HELPER"])
        from strix.core.paths import runs_base_dir
        from strix.interface.blue import BlueError, prepare_blue

        output = runs_base_dir() / (
            f"blue-{datetime.now(UTC):%Y%m%d-%H%M%S}-{os.getpid()}-{uuid4().hex[:8]}"
        )
        self._start_in_progress = True
        try:
            try:
                manifest = await asyncio.to_thread(
                    prepare_blue, target, output, model, approval, provider,
                    endpoint, case_id, pe_audit,
                )
            except BlueError as exc:
                raise ValueError(str(exc)) from exc
        finally:
            self._start_in_progress = False
        files = manifest["files"]
        manifest_path = output / "manifest.json"
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        scope_sha256 = hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.blue_preview = {
            "target": manifest["target"],
            "manifest": str(manifest_path),
            "manifest_sha256": manifest_sha256,
            "case_id": manifest["case_id"],
            "file_count": len(files),
            "total_bytes": sum(entry["size"] for entry in files),
            "scope_sha256": scope_sha256,
            "first_path": files[0]["path"],
            "first_sha256": files[0]["sha256"],
            "included_files": [entry["path"] for entry in files[:8]],
            "remaining_files": max(0, len(files) - 8),
            "operations": manifest["operations"],
            "sandbox": manifest["sandbox"],
            "model": manifest["model"],
            "provider": manifest["provider"],
            "approval": manifest["approval"],
            "endpoint": manifest["endpoint"],
            "pe_audit": manifest["pe_audit"],
            "binary_without_helper": manifest["pe_audit"] is None and any(
                Path(entry["path"]).suffix.lower() in {".exe", ".dll"} for entry in files
            ),
        }
        self._append_message(
            "Blue snapshot prepared. Review the scope and type its RUN phrase.", "info"
        )
        return dict(self.blue_preview)

    async def _blue_confirm(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        preview = self.blue_preview
        if preview is None:
            raise RuntimeError("No Blue preview is pending")
        phrase = self._required_string(payload, "phrase")
        if phrase != f"RUN {preview['manifest_sha256'][:8]}":
            raise ValueError("Blue confirmation phrase does not match the preview")
        current_digest = hashlib.sha256(Path(preview["manifest"]).read_bytes()).hexdigest()
        if current_digest != preview["manifest_sha256"]:
            raise ValueError("Blue manifest changed since preview; prepare a new run")
        self.setup_mode = False
        self.scan_started = True
        self.scan_state = "preparing"
        self._blue_task = asyncio.create_task(self._run_blue(preview["manifest"], preview))
        return {"started": True, "manifest": preview["manifest"]}

    async def _run_blue(self, manifest: str, preview: dict[str, Any]) -> None:
        from strix.interface.blue import _run_prepared

        self.scan_state = "running"
        self.notify_changed()
        try:
            outcome = await asyncio.to_thread(
                _run_prepared,
                Path(manifest),
                confirmed_phrase=f"RUN {preview['first_sha256'][:8]}",
                expected_manifest_sha256=preview["manifest_sha256"],
            )
        except Exception as exc:  # noqa: BLE001 - the TUI needs the run failure
            self.error = str(exc)
            self.scan_state = "failed"
        else:
            if outcome == "completed":
                self.scan_state = "completed"
                self._refresh_blue_findings(Path(manifest).parent)
            elif outcome in {"failed", "interrupted"}:
                self.scan_state = outcome
                self.error = f"Blue analysis {outcome}; inspect the saved run evidence."
            else:
                self.scan_state = "failed"
                self.error = f"Blue analysis returned unexpected status: {outcome!r}"
        self.notify_changed()

    async def _blue_cancel(self, _payload: dict[str, Any]) -> dict[str, Any]:
        self._require_setup_mutable()
        previous = self.blue_preview
        if previous is not None:
            from strix.interface.blue import BlueError, discard_prepared_blue

            try:
                await asyncio.to_thread(
                    discard_prepared_blue, Path(previous["manifest"]), previous["scope_sha256"]
                )
            except BlueError as exc:
                raise ValueError(str(exc)) from exc
            self.blue_preview = None
            self._append_message("Blue preview closed and its prepared snapshot removed.", "info")
        return {"cancelled": previous is not None}

    def _completed_blue_manifest(self) -> dict[str, Any]:
        from strix.interface.blue import inventory

        preview = self.blue_preview
        if preview is None or self.setup_mode or self.scan_state != "completed":
            raise RuntimeError("Finish a Blue run before requesting runtime observation")
        path = Path(preview["manifest"])
        manifest = json.loads(path.read_text(encoding="utf-8"))
        files = manifest.get("files")
        if (
            manifest.get("schema") != "strix-blue-local-v1"
            or manifest.get("status") != "completed"
            or manifest.get("output") != str(path.parent)
            or manifest.get("target") != preview["target"]
            or manifest.get("input_snapshot") != str(path.parent / "inputs")
            or not isinstance(files, list)
            or hashlib.sha256(
                json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            != preview["scope_sha256"]
        ):
            raise ValueError("Blue manifest changed or has not completed")
        if inventory(path.parent / "inputs") != files:
            raise ValueError("Blue snapshot changed since preparation")
        return manifest

    async def _blue_observe_preview(self, payload: dict[str, Any]) -> dict[str, Any]:
        from strix.interface import blue_runtime

        manifest = self._completed_blue_manifest()
        if self.blue_observation is not None and self.blue_observation["status"] in {
            "pending", "running"
        }:
            raise RuntimeError("Finish or cancel the current runtime request first")
        mode = self._required_string(payload, "mode")
        if mode not in {"launch", "attach"}:
            raise ValueError("Runtime mode must be launch or attach")
        relative_path = self._required_string(payload, "path")
        entry = next((item for item in manifest["files"] if item["path"] == relative_path), None)
        if entry is None:
            raise ValueError("Runtime target must be an included Blue snapshot file")
        try:
            seconds = float(payload.get("timeout_seconds", 5.0))
        except (TypeError, ValueError) as exc:
            raise ValueError("Runtime timeout must be a number") from exc
        if not 0.1 <= seconds <= 30.0:
            raise ValueError("Runtime timeout must be between 0.1 and 30 seconds")
        pid = payload.get("pid")
        if mode == "attach":
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                raise ValueError("Attach requires a positive PID")
        elif pid is not None:
            raise ValueError("Launch does not accept a PID")
        output = Path(manifest["output"])
        scope = Path(manifest["input_snapshot"])
        permit = blue_runtime.TargetPermit(
            scope_root=scope,
            target=scope / relative_path,
            sha256=entry["sha256"],
            allow_launch=mode == "launch",
            allow_attach=mode == "attach",
        )
        evidence = output / f"runtime-{mode}-{uuid4().hex}.jsonl"
        try:
            base_phrase = await asyncio.to_thread(
                blue_runtime.launch_confirmation_phrase, permit, evidence, seconds
            )
        except blue_runtime.RuntimeObservationError as exc:
            raise ValueError(str(exc)) from exc
        phrase = base_phrase
        if mode == "attach":
            bound = json.dumps([base_phrase, pid, "attach"], separators=(",", ":"))
            phrase = "ATTACH " + hashlib.sha256(bound.encode("utf-8")).hexdigest()[:20].upper()
        grant = self._blue_grant
        grant_eligible = bool(
            grant is not None
            and mode == "launch"
            and grant["manifest"] == str(Path(self.blue_preview["manifest"]).resolve())
            and grant["scope_sha256"] == self.blue_preview["scope_sha256"]
            and grant["path"] == str(permit.target)
            and grant["sha256"] == permit.sha256
            and grant["used"] < 3
            and grant["seconds_used"] + seconds <= 30.0
            and time.monotonic() < grant["expires_monotonic"]
        )
        grant_phrase = ""
        grant_expiry = ""
        if mode == "launch" and grant is None:
            grant_expiry = (datetime.now(UTC) + timedelta(minutes=10)).isoformat()
            binding = json.dumps(
                [str(Path(self.blue_preview["manifest"]).resolve()),
                 self.blue_preview["scope_sha256"], str(permit.target), permit.sha256,
                 "launch", 3, 30, grant_expiry, uuid4().hex],
                separators=(",", ":"),
            )
            grant_digest = hashlib.sha256(binding.encode("utf-8")).hexdigest()[:20].upper()
            grant_phrase = "GRANT " + grant_digest
        self._blue_observation_permit = permit
        self.blue_observation = {
            "status": "pending",
            "mode": mode,
            "path": str(permit.target),
            "sha256": permit.sha256,
            "timeout_seconds": seconds,
            "pid": pid,
            "evidence": str(evidence),
            "warning": blue_runtime.WARNING,
            "phrase": phrase,
            "grant_phrase": grant_phrase,
            "grant_eligible": grant_eligible,
            "grant_used": grant["used"] if grant is not None else 0,
            "grant_seconds_used": grant["seconds_used"] if grant is not None else 0.0,
            "grant_expires_utc": grant["expires_utc"] if grant is not None else grant_expiry,
        }
        return dict(self.blue_observation)

    async def _blue_observe_confirm(self, payload: dict[str, Any]) -> dict[str, Any]:
        from strix.interface import blue_runtime

        request = self.blue_observation
        permit = self._blue_observation_permit
        if request is None or request["status"] != "pending" or permit is None:
            raise RuntimeError("No runtime observation is pending")
        use_grant = payload.get("use_grant") is True
        phrase = "" if use_grant else self._required_string(payload, "phrase")
        create_grant = bool(request["grant_phrase"] and phrase == request["grant_phrase"])
        if use_grant and not request["grant_eligible"]:
            raise ValueError("This preview is not eligible for the runtime grant")
        if not use_grant and not create_grant and phrase != request["phrase"]:
            raise ValueError("Runtime confirmation phrase does not match this request")
        manifest = self._completed_blue_manifest()
        try:
            base_phrase = await asyncio.to_thread(
                blue_runtime.launch_confirmation_phrase,
                permit,
                Path(request["evidence"]),
                request["timeout_seconds"],
            )
        except blue_runtime.RuntimeObservationError as exc:
            raise ValueError(str(exc)) from exc
        expected = base_phrase
        if request["mode"] == "attach":
            bound = json.dumps([base_phrase, request["pid"], "attach"], separators=(",", ":"))
            expected = "ATTACH " + hashlib.sha256(bound.encode("utf-8")).hexdigest()[:20].upper()
        if not use_grant and not create_grant and phrase != expected:
            raise ValueError("Runtime target or evidence changed since preview")
        if use_grant or create_grant:
            self._consume_blue_grant(request, manifest, create_grant=create_grant)
            phrase = base_phrase
        request["status"] = "running"
        request.pop("phrase", None)
        request.pop("grant_phrase", None)
        self._blue_observation_task = asyncio.create_task(
            self._run_blue_observation(permit, dict(request), phrase)
        )
        return {"started": True, "evidence": request["evidence"]}

    def _consume_blue_grant(
        self, request: dict[str, Any], manifest: dict[str, Any], *, create_grant: bool
    ) -> None:
        from strix.interface.blue import _event

        if request["mode"] != "launch" or request["pid"] is not None:
            raise ValueError("Reusable grants are limited to launch actions")
        assert self.blue_preview is not None
        grant = self._blue_grant
        if create_grant:
            if grant is not None:
                raise ValueError("This Blue run already has a runtime grant")
            expires_utc = datetime.fromisoformat(request["grant_expires_utc"])
            remaining = (expires_utc - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                raise ValueError("Runtime grant preview expired; request a new preview")
            grant = {
                "id": request["grant_phrase"].split(" ", 1)[1],
                "manifest": str(Path(self.blue_preview["manifest"]).resolve()),
                "scope_sha256": self.blue_preview["scope_sha256"],
                "path": request["path"],
                "sha256": request["sha256"],
                "mode": "launch",
                "used": 0,
                "seconds_used": 0.0,
                "expires_utc": request["grant_expires_utc"],
                "expires_monotonic": time.monotonic() + min(remaining, 600.0),
            }
        if (
            grant is None
            or grant["manifest"] != str(Path(self.blue_preview["manifest"]).resolve())
            or grant["scope_sha256"] != self.blue_preview["scope_sha256"]
            or grant["path"] != request["path"]
            or grant["sha256"] != request["sha256"]
            or grant["mode"] != request["mode"]
            or grant["used"] >= 3
            or grant["seconds_used"] + request["timeout_seconds"] > 30.0
            or time.monotonic() >= grant["expires_monotonic"]
        ):
            raise ValueError("Runtime grant expired, exhausted, or does not match this request")
        output = Path(manifest["output"])
        if create_grant:
            summary = (
                f"grant {grant['id']}: scope {grant['scope_sha256']}; "
                f"target {grant['path']} SHA-256 {grant['sha256']}; launch; "
                f"max 3 actions, 30 seconds; expires {grant['expires_utc']}"
            )
            _event(output, "runtimeGrantCreated", summary)
            self._blue_grant = grant
        next_used = grant["used"] + 1
        next_seconds = grant["seconds_used"] + request["timeout_seconds"]
        summary = (
            f"grant {grant['id']}: used {next_used}/3; "
            f"reserved {next_seconds:g}/30 seconds; evidence {Path(request['evidence']).name}"
        )
        _event(output, "runtimeGrantUsed", summary)
        grant["used"] = next_used
        grant["seconds_used"] = next_seconds
        request["grant_used"] = next_used
        request["grant_seconds_used"] = next_seconds

    async def _run_blue_observation(
        self, permit: Any, request: dict[str, Any], phrase: str
    ) -> None:
        from strix.interface import blue_runtime
        from strix.interface.blue import _event

        try:
            result = await asyncio.to_thread(
                blue_runtime.observe_runtime,
                permit,
                mode=request["mode"],
                evidence_path=Path(request["evidence"]),
                timeout_seconds=request["timeout_seconds"],
                pid=request["pid"],
                confirmation_phrase=phrase if request["mode"] == "launch" else None,
                risk_acknowledged=True,
            )
        except Exception as exc:  # noqa: BLE001 - report failure beside the evidence path
            assert self.blue_observation is not None
            self.blue_observation.update(status="failed", error=str(exc))
            if Path(request["evidence"]).is_file():
                _event(
                    Path(request["evidence"]).parent,
                    "runtimeObservationFailed",
                    f"{request['mode']} failed; evidence: {Path(request['evidence']).name}",
                )
        else:
            assert self.blue_observation is not None
            self.blue_observation.update(
                status="completed",
                result_status=result.status,
                pid=result.pid,
                elapsed_seconds=result.elapsed_seconds,
                exit_code=result.exit_code,
            )
            _event(
                Path(request["evidence"]).parent,
                "runtimeObservation",
                f"{request['mode']} PID {result.pid}: {result.status}; "
                f"evidence: {Path(request['evidence']).name}",
            )
        self._blue_observation_permit = None
        self.notify_changed()

    async def _blue_observe_cancel(self, _payload: dict[str, Any]) -> dict[str, Any]:
        if self.blue_observation is None or self.blue_observation["status"] != "pending":
            raise RuntimeError("No runtime observation is pending")
        self.blue_observation = None
        self._blue_observation_permit = None
        return {"cancelled": True}

    def _refresh_blue_findings(self, output: Path) -> None:
        try:
            recorded = json.loads((output / "vulnerabilities.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = []
        self.blue_findings = [
            {
                "id": item["id"],
                "title": item.get("title", ""),
                "severity": item.get("severity", ""),
                "source_sha256": item.get("source_sha256", ""),
            }
            for item in recorded
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        ][:100]

    def _blue_handoff_review(self, payload: dict[str, Any]) -> dict[str, Any]:
        from strix.interface.blue_handoff import preview_handoff
        from strix.interface.blue_local import validate_loopback_endpoint
        from strix.report.cases import list_case_runs

        manifest = self._completed_blue_manifest()
        if self.blue_observation is not None and self.blue_observation["status"] == "running":
            raise RuntimeError("Finish the runtime observation before handing off findings")
        preview = self.blue_preview
        assert preview is not None
        output = Path(preview["manifest"]).parent
        finding_id = self._required_string(payload, "finding_id")
        scope = self._required_string(payload, "scope")
        if len(scope) > 4096:
            raise ValueError("Standard scope is too long")
        questions = payload.get("questions", [])
        if (
            not isinstance(questions, list)
            or len(questions) > 10
            or any(
                not isinstance(item, str) or not item.strip() or len(item) > 1024
                for item in questions
            )
        ):
            raise ValueError("Questions must be at most ten non-empty short strings")
        model = payload.get("model") or None
        endpoint = payload.get("endpoint") or None
        if bool(model) != bool(endpoint):
            raise ValueError("Provide both a local Standard model and endpoint, or neither")
        if model is not None:
            if not isinstance(model, str) or not model.startswith("openai/") or len(model) <= 7:
                raise ValueError("Standard's local model must use openai/MODEL")
            if not isinstance(endpoint, str):
                raise ValueError("Standard endpoint must be a loopback URL")
            validate_loopback_endpoint(endpoint)
        runs = [run for run in list_case_runs() if run.path.resolve() == output.resolve()]
        if len(runs) != 1 or runs[0].mode != "blue":
            raise ValueError("Completed Blue run is missing from the shared case catalog")
        findings_path = output / "vulnerabilities.json"
        findings_bytes = findings_path.read_bytes()
        recorded = json.loads(findings_bytes)
        if not isinstance(recorded, list):
            raise TypeError("Blue findings artifact must be a list")
        selected = [
            item for item in recorded
            if isinstance(item, dict) and item.get("id") == finding_id
        ]
        if len(selected) != 1:
            raise ValueError("Select one recorded Blue finding")
        finding = selected[0]
        source_sha256 = finding.get("source_sha256")
        if not isinstance(source_sha256, str) or source_sha256 not in {
            item["sha256"] for item in manifest["files"]
        }:
            raise ValueError("Finding source hash does not match the reviewed snapshot")
        finding_sha256 = hashlib.sha256(
            json.dumps(finding, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        review = {
            "run_selector": runs[0].selector,
            "case_id": runs[0].case_id,
            "target": manifest["target"],
            "snapshot": manifest["input_snapshot"],
            "manifest_sha256": hashlib.sha256(Path(preview["manifest"]).read_bytes()).hexdigest(),
            "findings_sha256": hashlib.sha256(findings_bytes).hexdigest(),
            "snapshot_sha256": preview["scope_sha256"],
            "finding_id": finding_id,
            "finding_title": str(finding.get("title") or ""),
            "finding_severity": str(finding.get("severity") or ""),
            "finding_evidence": str(finding.get("evidence") or ""),
            "finding_sha256": finding_sha256,
            "source_sha256": source_sha256,
            "scope": scope,
            "questions": [item.strip() for item in questions],
            "model": model,
            "endpoint": endpoint,
            "launch_ready": model is not None and endpoint is not None,
        }
        referenced = preview_handoff(
            runs[0].selector, [finding_id], review["questions"], scope, model, endpoint
        )
        review["handoff_preview_sha256"] = referenced["preview_sha256"]
        review["review_sha256"] = hashlib.sha256(
            json.dumps(review, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return review

    async def _blue_handoff_preview(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.blue_handoff is not None and self.blue_handoff["status"] in {
            "pending_stage", "staging", "launching"
        }:
            raise RuntimeError("Finish or close the current handoff first")
        review = await asyncio.to_thread(self._blue_handoff_review, payload)
        self.blue_handoff = {
            **review,
            "status": "pending_stage",
            "phrase": f"STAGE {review['review_sha256'][:8]}",
        }
        return dict(self.blue_handoff)

    async def _blue_handoff_stage(self, payload: dict[str, Any]) -> dict[str, Any]:
        from strix.interface.blue_handoff import stage_handoff

        handoff = self.blue_handoff
        if handoff is None or handoff["status"] != "pending_stage":
            raise RuntimeError("No reviewed handoff is pending")
        if self._required_string(payload, "phrase") != handoff["phrase"]:
            raise ValueError("Handoff staging phrase does not match the preview")
        request = {
            key: handoff[key] for key in ("finding_id", "scope", "questions", "model", "endpoint")
        }
        current = await asyncio.to_thread(self._blue_handoff_review, request)
        if current["review_sha256"] != handoff["review_sha256"]:
            raise ValueError("Blue evidence or handoff scope changed; request a new preview")
        handoff["status"] = "staging"
        self.notify_changed()
        stage: Path | None = None
        try:
            stage, record = await asyncio.to_thread(
                stage_handoff,
                handoff["run_selector"], [handoff["finding_id"]],
                handoff["questions"], handoff["scope"], handoff["model"],
                handoff["endpoint"],
                expected_preview_digest=handoff["handoff_preview_sha256"],
            )
            self._verify_staged_handoff(
                record, handoff, self._completed_blue_manifest()["files"]
            )
            record_sha256 = hashlib.sha256((stage / "handoff.json").read_bytes()).hexdigest()
        except Exception as exc:
            if stage is not None:
                self._discard_failed_handoff_stage(stage, record)
            handoff.update(status="stage_failed", error=str(exc))
            raise
        handoff.update(
            status="staged", stage_path=str(stage), staged_target=str(stage / "target"),
            record_sha256=record_sha256,
            phrase=f"STANDARD {record_sha256[:8]}" if handoff["launch_ready"] else "",
        )
        return dict(handoff)

    @staticmethod
    def _verify_staged_handoff(
        record: dict[str, Any], handoff: dict[str, Any], files: list[dict[str, Any]]
    ) -> None:
        if (
            record.get("files") != files
            or record.get("scope") != handoff["scope"]
            or record.get("standard_model") != handoff["model"]
            or record.get("standard_endpoint") != handoff["endpoint"]
        ):
            raise ValueError("Staged handoff differs from reviewed Blue evidence")
        staged_findings = record.get("findings")
        if not isinstance(staged_findings, list) or len(staged_findings) != 1:
            raise ValueError("Staged handoff has an unexpected finding count")
        staged_hash = hashlib.sha256(
            json.dumps(staged_findings[0], sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if staged_hash != handoff["finding_sha256"]:
            raise ValueError("Staged finding differs from reviewed Blue evidence")

    @staticmethod
    def _discard_failed_handoff_stage(stage: Path, record: dict[str, Any]) -> None:
        from strix.core.paths import runs_base_dir

        root = (runs_base_dir() / "handoffs").resolve(strict=True)
        if stage.is_symlink() or stage.resolve(strict=True).parent != root:
            return
        expected = {stage / "handoff.json"}
        files = record.get("files", [])
        if isinstance(files, list):
            expected.update(
                stage / "target" / item["path"]
                for item in files
                if isinstance(item, dict) and isinstance(item.get("path"), str)
            )
        actual = {path for path in stage.rglob("*") if path.is_file() or path.is_symlink()}
        if actual == expected and all(not path.is_symlink() for path in actual):
            shutil.rmtree(stage)
        else:
            (stage / "handoff.json").replace(stage / "handoff.invalid.json")

    async def _blue_handoff_launch(self, payload: dict[str, Any]) -> dict[str, Any]:
        from strix.interface.blue_handoff import launch_staged_handoff

        handoff = self.blue_handoff
        if handoff is None or handoff["status"] != "staged" or not handoff["launch_ready"]:
            raise RuntimeError("No launch-ready staged handoff is pending")
        if self._required_string(payload, "phrase") != handoff["phrase"]:
            raise ValueError("Standard launch phrase does not match the staged record")
        handoff["status"] = "launching"
        self.notify_changed()
        try:
            pid = await asyncio.to_thread(
                launch_staged_handoff,
                Path(handoff["stage_path"]), handoff["model"], handoff["endpoint"],
                expected_hash=handoff["record_sha256"],
            )
        except Exception as exc:
            handoff.update(status="staged", error=str(exc))
            raise
        handoff.update(status="launched", standard_pid=pid, phrase="")
        return {"launched": True, "pid": pid, "stage_path": handoff["stage_path"]}

    async def _blue_handoff_close(self, _payload: dict[str, Any]) -> dict[str, Any]:
        handoff = self.blue_handoff
        if handoff is not None and handoff["status"] in {"staging", "launching"}:
            raise RuntimeError("Wait for the handoff action to finish")
        self.blue_handoff = None
        return {"closed": handoff is not None}

    async def _send_message(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = self._required_string(payload, "agent_id")
        message = self._required_string(payload, "message")
        if self.coordinator is None:
            raise RuntimeError("Agent coordinator is unavailable")
        if self.scan_loop is None or self.scan_loop.is_closed():
            raise RuntimeError("Scan loop is not ready")
        self.live_view.record_user_message(agent_id, message)
        if self.scan_loop is asyncio.get_running_loop():
            delivered = await self.coordinator.send(
                agent_id,
                {"from": "user", "content": message, "type": "instruction"},
            )
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.send(
                    agent_id,
                    {"from": "user", "content": message, "type": "instruction"},
                ),
                self.scan_loop,
            )
            delivered = await asyncio.wrap_future(future)
        if not delivered:
            raise RuntimeError("Message could not be delivered")
        self.live_view.upsert_agent(agent_id, status="waiting", error_message=None)
        return {"sent": True}

    async def _stop_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = self._required_string(payload, "agent_id")
        agent = self.live_view.agents.get(agent_id)
        if agent is None:
            raise ValueError(f"Unknown agent: {agent_id}")
        status = str(agent.get("status", ""))
        if status not in _STOPPABLE_AGENT_STATUSES:
            raise RuntimeError(f"Agent '{agent_id}' cannot be stopped while {status or 'unknown'}")
        if self.coordinator is None or self.scan_loop is None or self.scan_loop.is_closed():
            raise RuntimeError("Scan loop is not ready")
        if self.scan_loop is asyncio.get_running_loop():
            accepted = await self.coordinator.cancel_descendants_graceful(agent_id)
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.coordinator.cancel_descendants_graceful(agent_id), self.scan_loop
            )
            accepted = await asyncio.wrap_future(future)
        if not accepted:
            raise RuntimeError(f"Agent '{agent_id}' is no longer active")
        return {"stopped": True}

    async def _open_viewer(self, _payload: dict[str, Any]) -> dict[str, Any]:
        if self.viewer_url:
            with contextlib.suppress(Exception):
                webbrowser.open(self.viewer_url)
            return {"status": "running", "url": self.viewer_url}
        blue_run_dir = (
            Path(self.blue_preview["manifest"]).parent
            if self.blue_preview is not None and self.scan_started
            else None
        )
        if self.report_state is None and blue_run_dir is None:
            self.viewer_status = "failed"
            return {"status": self.viewer_status, "error": "Scan output is not ready"}
        try:
            from strix.interface.tui.backend.messages import (
                send_user_message_to_agent,
            )
            from strix.interface.viewer.server import (
                authorized_url,
                bundle_is_built,
                serve,
            )

            if not bundle_is_built():
                self.viewer_status = "unavailable"
                return {"status": self.viewer_status, "error": "Viewer UI not built"}

            def steer(agent_id: str, message: str) -> bool:
                return send_user_message_to_agent(
                    coordinator=self.coordinator,
                    loop=self.scan_loop,
                    live_view=self.live_view,
                    target_agent_id=agent_id,
                    message=message,
                    notify_changed=self.notify_changed,
                    wait_for_delivery=True,
                )

            run_dir = (
                self.report_state.get_run_dir()
                if self.report_state is not None
                else blue_run_dir
            )
            assert run_dir is not None
            httpd, url, token = serve(
                run_dir,
                open_browser=True,
                steer_handler=steer if self.report_state is not None else None,
            )
            self._viewer_httpd = httpd
            self.viewer_url = authorized_url(url, token)
            self.viewer_status = "running"
            with contextlib.suppress(Exception):
                from strix.telemetry import posthog

                if self.report_state is None:
                    live = self.scan_state in {"preparing", "running"}
                else:
                    live = self.report_state.run_record.get("status") not in {
                        "completed", "stopped", "failed", "interrupted"
                    }
                posthog.viewer_opened(source="tui", live=live)
        except Exception:  # noqa: BLE001 - viewer startup failures must not crash the TUI
            self.viewer_status = "failed"
            return {"status": self.viewer_status, "error": "Viewer failed to start"}
        else:
            return {"status": self.viewer_status, "url": self.viewer_url}

    def close_viewer(self) -> None:
        httpd = self._viewer_httpd
        if httpd is None:
            return
        self._viewer_httpd = None
        with contextlib.suppress(Exception):
            httpd.shutdown()
            httpd.server_close()

    async def _quit(self, _payload: dict[str, Any]) -> dict[str, Any]:
        if self._blue_observation_task is not None and not self._blue_observation_task.done():
            raise RuntimeError("Runtime observation is active; wait for it to finish")
        self.close_viewer()
        if self._on_quit is not None:
            await self._on_quit()
        if self._blue_task is None or self._blue_task.done():
            self.scan_state = "stopped"
        return {"quitting": True}

    @staticmethod
    def _required_string(payload: dict[str, Any], name: str) -> str:
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value.strip()

    def _require_setup_mutable(self) -> None:
        if not self.setup_mode or self.scan_started or self._start_in_progress:
            raise RuntimeError("Setup can no longer be changed after the scan starts")
