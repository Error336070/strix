# Blue mode (experimental)

This fork adds a separate command for operator-led reviews of local software. It does not use Strix's normal scan agent, Docker image, proxy, browser, or attack tools. The first version reviews UTF-8 source files through a hash-checked copy. It does not perform dynamic testing or binary devirtualization.

## Prepare a run

From a source checkout with dependencies installed:

```powershell
.\.venv\Scripts\python.exe -m strix.interface.blue prepare C:\path\to\owned-source.cs --output C:\path\to\fresh-evidence-directory
```

`prepare` inventories the target, copies included files to `inputs`, hashes them, and prints the manifest. The output directory must be new and outside the target. It skips `.git`, `.venv`, `node_modules`, `__pycache__`, `bin`, and `obj`, and rejects symlinks. The limit is 500 files and 64 MiB. Check the printed file list before running.

For a locally hosted OpenAI-compatible model, add `--provider local --model MODEL --endpoint http://127.0.0.1:PORT/v1`. The local adapter accepts only `127.0.0.1` or `::1`, sends no tool definitions, and accepts at most 512 KiB of UTF-8 source per run.

## Start and monitor

```powershell
.\.venv\Scripts\python.exe -m strix.interface.blue run C:\path\to\fresh-evidence-directory\manifest.json
```

The command checks the target and input hashes again, shows the effective provider and approval setting, then asks you to type `RUN` plus the first file's hash prefix. It streams progress. Press Ctrl+C to stop. A stopped or failed manifest cannot be reused; prepare a new run.

The default Codex run uses the signed-in Codex subscription, requests Daybreak Blue on `gpt-6-sol`, disables shell, browser, web search, apps, plugins, and configured MCP servers, and supplies one host-owned `read_scope_file` tool. That tool accepts only an exact path from the manifest and checks the file hash before returning a bounded line range. The Codex turn uses a read-only sandbox with tool network access disabled. The command aborts if an unexpected MCP server starts or Codex reports another tool type.

`--approval auto-review` sets Codex's approval policy to `on-request` and reviewer to `auto_review`. The current static profile has no shell or write tool that should request escalation, so this option mainly verifies the integration path. Auto-review is not a path allowlist. Keep the default `deny` mode for ordinary source reviews.

## Evidence and limits

Each run directory contains `manifest.json`, the `inputs` copy, and, on completion, `report.md`. Codex runs also save `codex-settings.json`, `codex-events.jsonl`, and `codex-stderr.log`. The event log and source copy may contain sensitive data; keep the directory private. Findings are model analysis, not proof of runtime behavior. Check cited lines and validate material claims separately.

The app-server protocol is experimental. This Blue path is a standalone CLI workflow; it does not yet add Blue controls to Strix's TUI. Pause and resume, static binary inspection, controlled local execution, and live service testing are outside this first version.
