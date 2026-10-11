# Blue mode and the local case workspace

Blue reviews a bounded copy of authorized local software. Standard uses Strix's existing scan engine. They can run at the same time and write independent artifacts under a shared runs root. The local viewer combines their history by case ID. One run's model never receives another run's transcript automatically.

In the interactive Strix TUI, type `/blue PATH` on the setup screen to prepare a local Blue scope. Optional flags are `--case-id ID`, `--pe-audit PATH`, `--provider local --model MODEL --endpoint http://127.0.0.1:PORT/v1`, and `--approval auto-review` for the Codex route. Quote paths containing spaces. The preview shows the route, target, included files, permitted operations, full scope SHA-256, first file SHA-256, and manifest location. Review `manifest.json` for the complete file list when the preview shows more files than fit on screen. Type `RUN` followed by the first eight characters of the scope SHA-256 to start Blue. `/blue cancel` removes the prepared snapshot only if its manifest and files are unchanged; otherwise it leaves the evidence in place. The ordinary `strix blue prepare` and `strix blue run` commands remain available with their existing confirmation phrase.

## Shared run history

Set an absolute `STRIX_RUNS_DIR` before starting either mode. If unset, Strix uses `./strix_runs` as before. Register an older run directory or root without moving it:

```powershell
strix runs add-root C:\path\to\old\strix_runs
strix runs list
strix view RUN_NAME
```

The viewer shows registered Blue and Standard runs, findings, reviewed handoffs, and a live case timeline. Finding cards include recorded source or binary locations and hashes. Handoff cards show selected finding IDs, scope, questions, recorded target hashes, and matching Standard follow-ups. Its local session token grants access to history without email verification. Only the process that owns a live Standard run can steer its agents. The case view labels missing runtime evidence as missing.

## Prepare and run Blue

`strix blue prepare` prints a manifest with file paths, sizes, and SHA-256 hashes. It copies the files into `inputs`. Review that manifest, then run it:

```powershell
strix blue prepare C:\path\to\owned-source --case-id CASE_NAME
strix blue run C:\path\to\strix_runs\BLUE_RUN\manifest.json
```

The command asks you to type `RUN` followed by the first file's hash prefix. You can set `--output` to a fresh directory. The target and output must not overlap. Blue skips `.git`, `.venv`, `node_modules`, `__pycache__`, `bin`, and `obj`; it rejects symlinks. The current limit is 500 files and 64 MiB.

Blue accepts a Windows PE or .NET file as input. To give the Codex model a bounded metadata tool, pin the existing RE-LAB helper during preparation:

```powershell
strix blue prepare C:\path\to\owned.dll --pe-audit C:\path\to\RE-LAB\sources\pe-audit\bin\Release\net9.0\pe-audit.exe
```

The tool checks the snapshot and helper hashes before running the helper on the copy. It reports PE sections, .NET type names, and method counts. It does not recover methods or execute the target. Source reads return at most 200 UTF-8 lines per call.

## Approved runtime observation

After a Blue run completes, press `o` in its TUI view and enter `/observe launch "relative.exe" [seconds]` or `/observe attach "relative.exe" PID [seconds]`. The TUI displays the included snapshot executable, its SHA-256, the time limit, the local evidence path, and a warning that the program may contact services or change the host. Type the displayed `LAUNCH` or `ATTACH` phrase to approve that one action. For repeated launches of the same snapshot executable, the first preview also offers a `GRANT` phrase. That starts the first observation and permits at most three operator-entered launch actions, 30 total requested observation seconds, and 10 minutes. Each later action still needs its own `/observe` command, preview, and Enter. Attach always needs its own `ATTACH` phrase. The viewer's case timeline links saved observations to the Blue run.

The CLI can observe a completed run too:

```powershell
strix blue observe C:\path\to\BLUE_RUN\manifest.json --mode launch --file relative.exe --timeout 2
```

Both the CLI and TUI check and use the completed run's snapshot. A .NET executable may require its adjacent DLL, `.runtimeconfig.json`, and `.deps.json` files, so prepare the containing directory. Both flows require an explicit confirmation phrase. They save local JSONL process events and enforce a bounded observation time. Attached processes are observed without sending signals, and their image path must match the snapshot executable. The observer records the path hash at validation time; it cannot prove the exact bytes loaded by Windows. It does not isolate the target or contain child processes.

The default Codex route requests Daybreak Blue on `gpt-6-sol` and disables shell, browser, web search, apps, plugins, and configured MCP servers. It requests a read-only sandbox and no tool network access. `--approval auto-review` uses Codex Auto-review, but this static profile has no write or shell tool. A local OpenAI-compatible Blue model can be used with `--provider local --model MODEL --endpoint http://127.0.0.1:PORT/v1`; that adapter receives up to 512 KiB of UTF-8 source and no tools.

On completion, Blue saves `report.md` and validates any structured findings in the report against exact snapshot paths and hashes. Valid findings appear in `vulnerabilities.json`. Missing or invalid structured findings stay out of the count. Codex runs also save `codex-settings.json`, `codex-events.jsonl`, and `codex-stderr.log`.

## Reviewed Standard handoff

Choose one or more recorded Blue finding IDs. State the new scope and a local model route:

```powershell
strix blue handoff BLUE_RUN --finding F-1 --question "Can this reproduce on the staged copy?" --scope "Only the staged copy; no remote endpoints"
```

This writes `handoff.json` and a hash-checked target copy under `STRIX_RUNS_DIR\handoffs`. Review the evidence, selected findings, questions, scope, and copy. A model is optional while staging. To launch that exact copy later, run `strix blue handoff --staged HANDOFF_DIR --model openai/local-model --endpoint http://127.0.0.1:11434/v1 --launch` and confirm in the terminal. The target hashes are checked again before launch. Standard then starts through its normal CLI and Docker engine with its normal tools. The handoff passes only the selected findings and questions. It links the new run by case ID, parent run ID, and finding references. Blue's model route and approvals do not carry over.

Standard's local model requires an OpenAI-compatible endpoint on a loopback IP and a model name such as `openai/local-model`. Check that the chosen service can be reached by Strix's Docker runtime before launching. Standard may change the staged copy. The original audited target stays untouched.

## Current limits

The Go TUI shows Blue scope preview, confirmation, run status, and scoped runtime approvals. Process observation records start, exit, and timeout events; it does not provide method tracing or devirtualization. PE inspection covers metadata only. Grants last only for the current TUI process and cannot be renewed within that run; after expiry or exhaustion, actions return to per-action phrases. The case viewer displays missing evidence rather than implying those checks ran. A full Blue-to-Standard operator demo still needs an available local OpenAI-compatible Standard model.
