import { useState } from "react";
import type { CaseEvent, CaseFinding, CaseRun } from "@/data/serverSource";

type ModeFilter = "all" | "blue" | "standard";

interface Props {
  caseId: string;
  runs: CaseRun[];
  findings: CaseFinding[];
  events: CaseEvent[];
  onSelectRun: (runId: string) => void;
  onOpenFinding: (runId: string, findingId: string) => void;
}

export default function CaseWorkspaceView({
  caseId, runs, findings, events, onSelectRun, onOpenFinding,
}: Props) {
  const [mode, setMode] = useState<ModeFilter>("all");
  const visible = events.filter((event) => mode === "all" || event.mode === mode).slice().reverse();
  const runtimeCount = events.filter((event) => event.kind === "runtimeObservation").length;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold">Case workspace</h1>
        <p className="mt-1 font-mono text-xs text-[#888]">{caseId}</p>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <SummaryCell label="Linked runs" value={String(runs.length)} />
        <SummaryCell label="Recorded findings" value={String(findings.length)} />
        <SummaryCell label="Runtime observations" value={runtimeCount ? String(runtimeCount) : "Missing evidence"} />
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
        {findings.map((finding) => (
          <button
            key={`${finding.run_id}:${finding.id}`}
            onClick={() => onOpenFinding(finding.run_id, finding.id)}
            className="block w-full rounded-lg border border-[#333] p-3 text-left text-sm hover:border-[#777]"
          >
            <span className="uppercase text-[#aaa]">{finding.severity}</span>
            <span> · {finding.title}</span>
            <span className="ml-2 font-mono text-xs text-[#777]">{finding.run_id}</span>
          </button>
        ))}
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
