import { useState } from "react";
import type { CaseEvent, CaseFinding, CaseHandoff, CaseRun, RuntimeObservationCounts } from "@/data/serverSource";

type ModeFilter = "all" | "blue" | "standard";

interface Props {
  caseId: string;
  runs: CaseRun[];
  findings: CaseFinding[];
  handoffs: CaseHandoff[];
  events: CaseEvent[];
  runtimeObservations: RuntimeObservationCounts;
  onSelectRun: (selector: string) => void;
  onOpenFinding: (selector: string, findingId: string) => void;
  onOpenEvent: (event: CaseEvent) => void;
}

export default function CaseWorkspaceView({
  caseId, runs, findings, handoffs, events, runtimeObservations, onSelectRun, onOpenFinding, onOpenEvent,
}: Props) {
  const [mode, setMode] = useState<ModeFilter>("all");
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null);
  const visible = events.filter((event) => mode === "all" || event.mode === mode).slice().reverse();
  const matchesParent = (recorded: string, selector: string, runId: string) =>
    recorded === selector || (recorded === runId && runs.filter((run) => run.run_id === runId).length === 1);
  const standardFollowUps = (parentSelector: string, parentRunId: string, findingRefs: string[]) => runs.filter((run) =>
    run.mode === "standard" && run.parent_run_id !== null && matchesParent(run.parent_run_id, parentSelector, parentRunId)
      && findingRefs.every((ref) => run.finding_refs.includes(ref))
  );

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold">Case workspace</h1>
        <p className="mt-1 font-mono text-xs text-[#888]">{caseId}</p>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <SummaryCell label="Linked runs" value={String(runs.length)} />
        <SummaryCell label="Recorded findings" value={String(findings.length)} />
        <SummaryCell label="Case runtime observations" value={runtimeObservations.total ? String(runtimeObservations.total) : "Missing evidence"} />
      </div>
      <section className="space-y-2">
        <h2 className="font-semibold">Runs</h2>
        {runs.map((run) => (
          <button
            key={run.selector}
            onClick={() => onSelectRun(run.selector)}
            className="block w-full rounded-lg border border-[#333] p-3 text-left text-sm hover:border-[#777]"
          >
            <span className="uppercase text-[#aaa]">{run.mode}</span>
            <span> · {run.run_id} · {run.status} · {run.findings} findings</span>
            {run.started_at && <span className="text-[#888]"> · {formatTime(run.started_at)}</span>}
            {run.parent_run_id && <span className="text-[#888]"> · from {run.parent_run_id}</span>}
          </button>
        ))}
      </section>
      <section className="space-y-2">
        <h2 className="font-semibold">Findings</h2>
        {findings.length === 0 && <p className="text-sm text-[#888]">No structured findings recorded.</p>}
        {findings.map((finding) => {
          const stages = handoffs.filter((handoff) => matchesParent(handoff.parent_run_id, finding.run_selector, finding.run_id) && handoff.finding_refs.includes(finding.id));
          const followUps = standardFollowUps(finding.run_selector, finding.run_id, [finding.id]);
          return (
          <button
            key={`${finding.run_selector}:${finding.id}`}
            onClick={() => onOpenFinding(finding.run_selector, finding.id)}
            className="block w-full rounded-lg border border-[#333] p-3 text-left text-sm hover:border-[#777]"
          >
            <span className="uppercase text-[#aaa]">{finding.severity}</span>
            <span> · {finding.title}</span>
            <span className="ml-2 font-mono text-xs text-[#777]">{finding.run_id}</span>
            {finding.locations.length ? finding.locations.map((location, index) => (
              <span key={`${location.path}:${index}`} className="mt-1 block break-all font-mono text-xs text-[#aaa]">
                {location.path}{location.line ? `:${location.line}` : ""}
                {location.sha256 ? ` · recorded SHA-256 ${location.sha256}` : " · hash not recorded"}
              </span>
            )) : <span className="mt-1 block text-xs text-[#888]">Exact source or binary location missing</span>}
            {finding.evidence && <span className="mt-1 block break-words text-xs text-[#aaa]">Evidence: {finding.evidence}</span>}
            <span className="mt-1 block text-xs text-[#aaa]">
              {stages.length ? `Staged: ${stages.map((stage) => stage.id).join(", ")}` : "No staged handoff"}
              {` · Matching Standard runs: ${followUps.length ? followUps.map((run) => run.run_id).join(", ") : "none"}`}
              {` · Runtime evidence: ${runtimeObservations.by_run[finding.run_selector] ? "run-level only" : "missing"}`}
            </span>
          </button>
          );
        })}
      </section>
      <section className="space-y-2">
        <h2 className="font-semibold">Reviewed handoffs</h2>
        {handoffs.length === 0 && <p className="text-sm text-[#888]">No staged handoff for this case.</p>}
        {handoffs.map((handoff, index) => {
          const parent = runs.find((run) => matchesParent(handoff.parent_run_id, run.selector, run.run_id));
          const followUps = standardFollowUps(parent?.selector ?? handoff.parent_run_id, parent?.run_id ?? handoff.parent_run_id, handoff.finding_refs);
          return (
            <article key={`${handoff.id}:${handoff.parent_run_id}:${index}`} className="rounded-lg border border-[#333] p-4 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-mono font-semibold">{handoff.id}</h3>
                <span className="rounded border border-[#444] px-2 py-0.5 text-xs text-[#aaa]">
                  {handoff.launch_ready ? "Model route supplied" : "Review only · model route missing"}
                </span>
              </div>
              <p className="mt-2 text-xs text-[#aaa]">Blue run: {handoff.parent_run_id} · Selected findings: {handoff.finding_refs.join(", ") || "none recorded"}</p>
              <p className="mt-2 whitespace-pre-wrap">Scope: {handoff.scope || "Missing scope"}</p>
              <div className="mt-2">
                <h4 className="text-xs font-semibold text-[#aaa]">Questions for Standard</h4>
                {handoff.questions.length ? <ul className="list-disc pl-5">{handoff.questions.map((question, index) => <li key={index}>{question}</li>)}</ul> : <p className="text-xs text-[#888]">None recorded</p>}
              </div>
              <div className="mt-2">
                <h4 className="text-xs font-semibold text-[#aaa]">Recorded target hashes</h4>
                {handoff.files.length ? <ul className="space-y-1">{handoff.files.map((file, fileIndex) => <li key={`${file.path}:${fileIndex}`} className="break-all font-mono text-xs">{file.path} · SHA-256 {file.sha256}</li>)}</ul> : <p className="text-xs text-[#888]">No file hashes recorded</p>}
              </div>
              <div className="mt-3 text-xs text-[#aaa]">
                <p>Matching Standard runs use the Blue parent and selected finding references.</p>
                {followUps.length ? followUps.map((run) => <button key={run.selector} className="mt-1 mr-2 underline hover:text-white" onClick={() => onSelectRun(run.selector)}>{run.run_id}</button>) : <p className="mt-1">No matching Standard run recorded.</p>}
              </div>
            </article>
          );
        })}
      </section>
      <section className="space-y-2">
        <div className="flex gap-2">
          <h2 className="mr-auto font-semibold">Recent activity (latest 500)</h2>
          {(["all", "blue", "standard"] as const).map((item) => (
            <button
              key={item}
              onClick={() => setMode(item)}
              className={`rounded border px-2 text-xs capitalize ${mode === item ? "border-white" : "border-[#444] text-[#888]"}`}
            >
              {item}
            </button>
          ))}
        </div>
        <div className="max-h-[32rem] space-y-1 overflow-y-auto">
          {visible.length === 0 && <p className="text-sm text-[#888]">No recorded activity in this filter.</p>}
          {visible.map((event) => {
            const isRuntime = event.kind === "runtimeObservation" || event.kind === "runtimeObservationFailed";
            const evidenceFile = event.evidence_file;
            return (
              <div key={event.id} className="rounded border border-[#222] text-xs">
                <button
                  onClick={() => isRuntime ? setExpandedEvent(expandedEvent === event.id ? null : event.id) : onOpenEvent(event)}
                  className="block w-full px-3 py-2 text-left hover:bg-[#111]"
                  aria-expanded={isRuntime ? expandedEvent === event.id : undefined}
                >
                  <span className="text-[#888]">{formatTime(event.timestamp)} · {event.mode} · {event.run_id}</span>
                  <span className="ml-2 text-white">{event.summary}</span>
                </button>
                {isRuntime && expandedEvent === event.id && (
                  <div className="flex flex-wrap gap-3 border-t border-[#222] px-3 py-2 text-[#aaa]">
                    {evidenceFile ? (
                      <a
                        className="underline hover:text-white"
                        href={`/api/case/evidence?run=${encodeURIComponent(event.run_selector)}&file=${encodeURIComponent(evidenceFile)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        Open saved runtime evidence ({evidenceFile})
                      </a>
                    ) : <span>Exact runtime evidence file not recorded.</span>}
                    <button className="underline hover:text-white" onClick={() => onSelectRun(event.run_selector)}>Open run overview</button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function formatTime(value: string): string {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function SummaryCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[#333] p-4">
      <div className="text-xs text-[#888]">{label}</div>
      <div className="mt-1 text-xl">{value}</div>
    </div>
  );
}
