import type { Vulnerability } from "@/types/issues";
import {
  parseRunJson,
  parseVulnerabilitiesJson,
  type ParsedRunSummary,
} from "@/lib/local-run-parser";

/**
 * Data seam for the local viewer: fetches against the local Python server's
 * JSON endpoints (same origin, relative URLs), producing the in-memory
 * `LoadedRun` shape the UI renders plus a `finished` flag driving live polling.
 *
 * The server serves a live in-progress run and a finished one identically; the
 * only signal is `run.finished`.
 */

/** A transcript agent as emitted by GET /api/transcript (already parsed). */
export interface TranscriptAgent {
  id: string;
  name: string;
  parent_id: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

/** Chat/tool event data as emitted by GET /api/transcript. */
export interface TranscriptEvent {
  id: string;
  type: "chat" | "tool";
  agent_id: string;
  timestamp: string;
  version: number;
  data: Record<string, unknown>;
}

export interface Transcript {
  agents: TranscriptAgent[];
  events: TranscriptEvent[];
}

/**
 * One MCP connection's non-secret status, as persisted to run.json by the
 * engine under `mcp_connection_status` and surfaced verbatim by GET /api/run.
 * Only name / provider / tool_count / dead ride here; never config, url, or
 * token. `dead` means the connection's live session gave up reconnecting.
 */
export interface McpConnectionStatus {
  name: string;
  provider: string | null;
  toolCount: number;
  dead: boolean;
}

/**
 * Read the MCP connection roster out of a raw run record. Tolerates the field
 * being absent (older runs, or a run with no MCP) and any malformed entry,
 * yielding an empty list rather than throwing.
 */
export function parseMcpConnectionStatus(raw: Record<string, unknown>): McpConnectionStatus[] {
  const list = raw?.mcp_connection_status;
  if (!Array.isArray(list)) return [];
  return list.flatMap((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
    const record = entry as Record<string, unknown>;
    const name = typeof record.name === "string" ? record.name.trim() : "";
    if (!name) return [];
    const provider = typeof record.provider === "string" && record.provider.trim() ? record.provider.trim() : null;
    const toolCount = typeof record.tool_count === "number" ? record.tool_count : 0;
    const dead = record.dead === true;
    return [{ name, provider, toolCount, dead }];
  });
}

export interface LoadedRun {
  summary: ParsedRunSummary;
  /** Whole raw run record (for llm_usage, targets_info details, etc.). */
  raw: Record<string, unknown>;
  finished: boolean;
  vulnerabilities: Vulnerability[];
  reportMarkdown: string | null;
  transcript: Transcript;
}

async function getJson(path: string): Promise<unknown> {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} responded ${res.status}`);
  return res.json();
}

/** Build a ``?run=<name>`` suffix for run-scoped data endpoints. */
function runQuery(runName?: string | null): string {
  return runName ? `?run=${encodeURIComponent(runName)}` : "";
}

export async function fetchRunSummary(runName?: string | null): Promise<{
  summary: ParsedRunSummary;
  raw: Record<string, unknown>;
  finished: boolean;
}> {
  const raw = (await getJson("/api/run" + runQuery(runName))) as Record<string, unknown>;
  // parseRunJson tolerates extra keys and takes raw TEXT.
  const summary = parseRunJson(JSON.stringify(raw));
  const finished = raw.finished === true;
  return { summary, raw, finished };
}

export async function fetchVulnerabilities(
  runId: string | null,
  runName?: string | null
): Promise<Vulnerability[]> {
  const arr = await getJson("/api/vulnerabilities" + runQuery(runName));
  return parseVulnerabilitiesJson(JSON.stringify(arr), runId);
}

export async function fetchReportMarkdown(runName?: string | null): Promise<string | null> {
  const obj = (await getJson("/api/report" + runQuery(runName))) as { markdown?: string };
  return obj?.markdown ?? null;
}

export async function fetchTranscript(runName?: string | null): Promise<Transcript> {
  const obj = (await getJson("/api/transcript" + runQuery(runName))) as Partial<Transcript>;
  return {
    agents: Array.isArray(obj?.agents) ? obj.agents : [],
    events: Array.isArray(obj?.events) ? obj.events : [],
  };
}

/** One-shot fetch of every endpoint (used on mount and on final settle). */
export async function fetchAll(runName?: string | null): Promise<LoadedRun> {
  const { summary, raw, finished } = await fetchRunSummary(runName);
  const [vulnerabilities, reportMarkdown, transcript] = await Promise.all([
    fetchVulnerabilities(summary.runId, runName).catch(() => [] as Vulnerability[]),
    fetchReportMarkdown(runName).catch(() => null),
    fetchTranscript(runName).catch(() => ({ agents: [], events: [] }) as Transcript),
  ]);
  return { summary, raw, finished, vulnerabilities, reportMarkdown, transcript };
}

// ---------------------------------------------------------------------------
// Run history + email auth + report send
//
// These endpoints back the "Your runs" sidebar section. Auth and report-send
// responses carry a meaningful JSON body on non-2xx statuses (an ``error``
// code), so they read the body regardless of status rather than throwing.
// ---------------------------------------------------------------------------

export interface RunSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RunListEntry {
  name: string;
  selector: string;
  mode: "blue" | "standard";
  case_id: string;
  parent_run_id: string | null;
  finding_refs: string[];
  target: string | null;
  scan_mode: string | null;
  status: string | null;
  start_time: string | null;
  end_time: string | null;
  finished: boolean;
  severity_counts: RunSeverityCounts;
}

export interface CaseRun {
  run_id: string;
  selector: string;
  case_id: string;
  mode: "blue" | "standard";
  parent_run_id: string | null;
  finding_refs: string[];
  status: string;
  started_at: string;
  target: string;
  findings: number;
}

export interface CaseEvent {
  id: string;
  run_id: string;
  run_selector: string;
  mode: "blue" | "standard";
  timestamp: string;
  kind: string;
  summary: string;
  finding_id?: string;
  evidence_file?: string;
}

export interface CaseFinding {
  run_id: string;
  run_selector: string;
  id: string;
  title: string;
  severity: string;
  locations: { path: string; line: number | null; sha256: string | null }[];
  evidence: string;
}

export interface CaseHandoff {
  id: string;
  parent_run_id: string;
  finding_refs: string[];
  scope: string;
  questions: string[];
  files: { path: string; sha256: string }[];
  launch_ready: boolean;
  created_at: string;
}

export interface RuntimeObservationCounts {
  total: number;
  by_run: Record<string, number>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseCaseHandoffs(value: unknown): CaseHandoff[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (!isRecord(entry) || typeof entry.id !== "string" || typeof entry.parent_run_id !== "string") return [];
    const files = Array.isArray(entry.files) ? entry.files.flatMap((file) =>
      isRecord(file) && typeof file.path === "string" && typeof file.sha256 === "string"
        ? [{ path: file.path, sha256: file.sha256 }]
        : []
    ) : [];
    return [{
      id: entry.id,
      parent_run_id: entry.parent_run_id,
      finding_refs: Array.isArray(entry.finding_refs) ? entry.finding_refs.filter((ref): ref is string => typeof ref === "string") : [],
      scope: typeof entry.scope === "string" ? entry.scope : "",
      questions: Array.isArray(entry.questions) ? entry.questions.filter((question): question is string => typeof question === "string") : [],
      files,
      launch_ready: entry.launch_ready === true,
      created_at: typeof entry.created_at === "string" ? entry.created_at : "",
    }];
  });
}

function parseCaseRuns(value: unknown): CaseRun[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (!isRecord(entry) || typeof entry.run_id !== "string" || typeof entry.selector !== "string") return [];
    return [{
      run_id: entry.run_id,
      selector: entry.selector,
      case_id: typeof entry.case_id === "string" ? entry.case_id : "",
      mode: entry.mode === "blue" ? "blue" : "standard",
      parent_run_id: typeof entry.parent_run_id === "string" ? entry.parent_run_id : null,
      finding_refs: Array.isArray(entry.finding_refs) ? entry.finding_refs.filter((ref): ref is string => typeof ref === "string") : [],
      status: typeof entry.status === "string" ? entry.status : "unknown",
      started_at: typeof entry.started_at === "string" ? entry.started_at : "",
      target: typeof entry.target === "string" ? entry.target : "",
      findings: typeof entry.findings === "number" ? entry.findings : 0,
    }];
  });
}

function parseCaseFindings(value: unknown): CaseFinding[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((entry) => {
    if (!isRecord(entry) || typeof entry.run_id !== "string" || typeof entry.run_selector !== "string" || typeof entry.id !== "string") return [];
    const locations = Array.isArray(entry.locations) ? entry.locations.flatMap((location) =>
      isRecord(location) && typeof location.path === "string"
        ? [{ path: location.path, line: typeof location.line === "number" ? location.line : null,
          sha256: typeof location.sha256 === "string" ? location.sha256 : null }]
        : []
    ) : [];
    return [{
      run_id: entry.run_id,
      run_selector: entry.run_selector,
      id: entry.id,
      title: typeof entry.title === "string" ? entry.title : "Untitled finding",
      severity: typeof entry.severity === "string" ? entry.severity : "unknown",
      locations,
      evidence: typeof entry.evidence === "string" ? entry.evidence : "",
    }];
  });
}

export async function fetchCase(runName?: string | null): Promise<{ case_id: string; runs: CaseRun[]; findings: CaseFinding[]; handoffs: CaseHandoff[]; runtime_observations: RuntimeObservationCounts }> {
  const value = await getJson("/api/case" + runQuery(runName));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid case response");
  const record = value as Record<string, unknown>;
  const aggregate = isRecord(record.runtime_observations) ? record.runtime_observations : {};
  const rawByRun = isRecord(aggregate.by_run) ? aggregate.by_run : {};
  const byRun = Object.fromEntries(Object.entries(rawByRun).filter((entry): entry is [string, number] => typeof entry[1] === "number"));
  return {
    case_id: typeof record.case_id === "string" ? record.case_id : "",
    runs: parseCaseRuns(record.runs),
    findings: parseCaseFindings(record.findings),
    handoffs: parseCaseHandoffs(record.handoffs),
    runtime_observations: { total: typeof aggregate.total === "number" ? aggregate.total : 0, by_run: byRun },
  };
}

export async function fetchCaseTimeline(runName?: string | null): Promise<CaseEvent[]> {
  const value = await getJson("/api/case/timeline" + runQuery(runName));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid timeline response");
  const events = (value as Record<string, unknown>).events;
  return Array.isArray(events) ? events as CaseEvent[] : [];
}

export interface RunsPayload {
  locked: boolean;
  count: number;
  runs: RunListEntry[];
}

export interface AuthStatus {
  verified: boolean;
  email: string | null;
}

export type OtpStartResult = { ok: true } | { ok: false; error: string };
export type OtpVerifyResult =
  | { verified: true; email: string }
  | { verified: false; error: string };
export type SendReportResult =
  | { ok: true; password: string; filename: string }
  | { ok: false; error: string };

async function postJson(
  path: string,
  body: Record<string, unknown>
): Promise<{ ok: boolean; status: number; data: Record<string, unknown> }> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  let data: Record<string, unknown> = {};
  try {
    const parsed = await res.json();
    if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>;
  } catch {
    /* empty or non-JSON body */
  }
  return { ok: res.ok, status: res.status, data };
}

export async function fetchRuns(): Promise<RunsPayload> {
  const obj = (await getJson("/api/runs")) as Partial<RunsPayload>;
  return {
    locked: obj?.locked ?? true,
    count: typeof obj?.count === "number" ? obj.count : 0,
    runs: Array.isArray(obj?.runs) ? (obj.runs as RunListEntry[]) : [],
  };
}

export interface Capabilities {
  can_steer: boolean;
  owner_run: string;
}

export type SteerResult = { ok: true } | { ok: false; error: string };

/** GET /api/capabilities. can_steer is true only inside a live in-TUI scan. */
export async function fetchCapabilities(): Promise<Capabilities> {
  const obj = (await getJson("/api/capabilities")) as Partial<Capabilities>;
  const owner_run = typeof obj?.owner_run === "string" ? obj.owner_run : "";
  return { can_steer: obj?.can_steer === true && owner_run.length > 0, owner_run };
}

/** POST /api/agents/steer. Sends a steering instruction to a running agent. */
export async function steerAgent(runName: string, agentId: string, message: string): Promise<SteerResult> {
  const { ok, data } = await postJson("/api/agents/steer", {
    run: runName,
    agent_id: agentId,
    message,
  });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export type SubmitFeedbackResult = { ok: true } | { ok: false; error: string };

/**
 * POST /api/feedback. Sends a feedback message plus a work email (no
 * verification) to the local server, which relays it to Strix.
 */
export async function submitFeedback(
  message: string,
  email: string
): Promise<SubmitFeedbackResult> {
  const { ok, data } = await postJson("/api/feedback", { message, email });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function fetchAuthStatus(): Promise<AuthStatus> {
  const obj = (await getJson("/api/auth/status")) as Partial<AuthStatus>;
  return { verified: obj?.verified === true, email: obj?.email ?? null };
}

export async function otpStart(email: string): Promise<OtpStartResult> {
  const { ok, data } = await postJson("/api/auth/otp/start", { email });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function otpVerify(email: string, code: string): Promise<OtpVerifyResult> {
  const { ok, data } = await postJson("/api/auth/otp/verify", { email, code });
  if (ok && data.verified === true) {
    return { verified: true, email: String(data.email ?? email) };
  }
  return { verified: false, error: String(data.error ?? "invalid_code") };
}

export async function forgetAuth(): Promise<void> {
  await postJson("/api/auth/forget", {});
}

export async function sendReport(runName?: string | null): Promise<SendReportResult> {
  const { ok, data } = await postJson("/api/report/send", runName ? { run: runName } : {});
  if (ok && data.ok === true) {
    return {
      ok: true,
      password: String(data.password ?? ""),
      filename: String(data.filename ?? "strix-report.pdf"),
    };
  }
  return { ok: false, error: String(data.error ?? "unavailable") };
}
