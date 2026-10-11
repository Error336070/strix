import { useState } from "react";
import type { CaseEvent, CaseFinding, CaseHandoff, CaseRun } from "@/data/serverSource";

type ModeFilter = "all" | "blue" | "standard";

interface Props {
  caseId: string;
  runs: CaseRun[];
  findings: CaseFinding[];
  handoffs: CaseHandoff[];
  events: CaseEvent[];
  onSelectRun: (runId: string) => void;
  onOpenFinding: (runId: string, findingId: string) => void;
}

export default function CaseWorkspaceView({
  caseId, runs, findings, handoffs, events, onSelectRun, onOpenFinding,
}: Props) {
  const [mode, setMode] = useState<ModeFilter>("all");
  const visible = events.filter((event) => mode === "all" || event.mode === mode).slice().reverse();
  const runtimeCount = events.filter((event) => event.kind === "runtimeObservation").length;
  const standardFollowUps = (parentRunId: string, findingRefs: string[]) => runs.filter((run) =>
    run.mode === "standard" && run.parent_run_id === parentRunId
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
        <SummaryCell label="Case runtime observations" value={runtimeCount ? String(runtimeCount) : "Missing evidence"} />
      </div>
      <section className="space-y-2">
        <h2 className="font-semibold">Runs</h2>
        {runs.map((run) => (
          <button
            key={run.run_id}
            onClick={() => onSelectRun(run.run_id)}
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
          const stages = handoffs.filter((handoff) => handoff.parent_run_id === finding.run_id && handoff.finding_refs.includes(finding.id));
          const followUps = standardFollowUps(finding.run_id, [finding.id]);
          return (
          <button
            key={`${finding.run_id}:${finding.id}`}
            onClick={() => onOpenFinding(finding.run_id, finding.id)}
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
              {` · Runtime evidence: ${runtimeCount ? "case-level only" : "missing"}`}
            </span>
          </button>
          );
        })}
      </section>
      <section className="space-y-2">
        <h2 className="font-semibold">Reviewed handoffs</h2>
        {handoffs.length === 0 && <p className="text-sm text-[#888]">No staged handoff for this case.</p>}
        {handoffs.map((handoff) => {
          const followUps = standardFollowUps(handoff.parent_run_id, handoff.finding_refs);
          return (
            <article key={handoff.id} className="rounded-lg border border-[#333] p-4 text-sm">
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
                {handoff.files.length ? <ul className="space-y-1">{handoff.files.map((file) => <li key={file.path} className="break-all font-mono text-xs">{file.path} · SHA-256 {file.sha256}</li>)}</ul> : <p className="text-xs text-[#888]">No file hashes recorded</p>}
              </div>
              <div className="mt-3 text-xs text-[#aaa]">
                <p>Matching Standard runs use the Blue parent and selected finding references.</p>
                {followUps.length ? followUps.map((run) => <button key={run.run_id} className="mt-1 mr-2 underline hover:text-white" onClick={() => onSelectRun(run.run_id)}>{run.run_id}</button>) : <p className="mt-1">No matching Standard run recorded.</p>}
              </div>
            </article>
          );
        })}
      </section>
      <section className="space-y-2">
        <div className="flex gap-2">
          <h2 className="mr-auto font-semibold">Live activity</h2>
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
          {visible.map((event) => (
            <button
              key={event.id}
              onClick={() => onSelectRun(event.run_id)}
              className="block w-full rounded border border-[#222] px-3 py-2 text-left text-xs hover:border-[#555]"
            >
              <span className="text-[#888]">{formatTime(event.timestamp)} · {event.mode} · {event.run_id}</span>
              <span className="ml-2 text-white">{event.summary}</span>
            </button>
          ))}
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
