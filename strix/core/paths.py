"""Run directory path helpers."""

from __future__ import annotations

import os
from pathlib import Path


RUNS_DIR_NAME = "strix_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    return runs_base_dir(cwd=cwd) / run_name


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def runs_base_dir(*, cwd: Path | None = None) -> Path:
    if cwd is None and (configured := os.environ.get("STRIX_RUNS_DIR")):
        root = Path(configured).expanduser()
        if not root.is_absolute():
            raise ValueError("STRIX_RUNS_DIR must be an absolute path")
        return root.resolve()
    return (cwd or Path.cwd()) / RUNS_DIR_NAME


def latest_run_dir(*, cwd: Path | None = None) -> Path | None:
    base = runs_base_dir(cwd=cwd)
    if not base.is_dir():
        return None
    candidates = [child for child in base.iterdir() if run_record_path(child).is_file()]
    if not candidates:
        return None
    # run.json is rewritten on status/end changes, so its mtime tracks activity
    # more reliably than the directory mtime (a live run sorts to the top).
    return max(candidates, key=lambda child: run_record_path(child).stat().st_mtime)
