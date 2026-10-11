"""Inspect and extend the local run catalog without moving artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from strix.report.cases import add_catalog_root, catalog_roots, list_case_runs


def run_runs(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="strix runs")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List registered Blue and Standard runs")
    commands.add_parser("roots", help="Show the shared run roots")
    add = commands.add_parser("add-root", help="Register a legacy run directory or root")
    add.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    if args.command == "add-root":
        try:
            print(add_catalog_root(args.path))  # noqa: T201
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    elif args.command == "roots":
        for root in catalog_roots():
            print(root)  # noqa: T201
    else:
        for run in list_case_runs():
            print(json.dumps(run.public(), ensure_ascii=False))  # noqa: T201
    return 0
