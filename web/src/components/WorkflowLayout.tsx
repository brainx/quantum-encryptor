import type { ReactNode } from "react";
import type { Capability } from "../api";
import type { WorkflowPhase } from "../lib/workflow";
import { Notice } from "./Notice";

export type WorkflowLayoutProps = {
  title: string;
  description: string;
  phase: WorkflowPhase;
  capability: Capability;
  busy?: boolean;
  children: ReactNode;
};

const phaseLabels: Record<WorkflowPhase, string> = {
  select: "Select",
  review: "Review",
  complete: "Complete"
};

export function WorkflowLayout({ title, description, phase, capability, busy = false, children }: WorkflowLayoutProps) {
  return (
    <section aria-busy={busy || undefined} className="workflow-layout">
      <header className="workflow-header">
        <h1>{title}</h1>
        <p>{description}</p>
      </header>
      <ol aria-label="Workflow progress" className="workflow-phases">
        {(Object.keys(phaseLabels) as WorkflowPhase[]).map((value) => (
          <li aria-current={phase === value ? "step" : undefined} className={phase === value ? "is-current" : undefined} key={value}>
            {phaseLabels[value]}
          </li>
        ))}
      </ol>
      {!capability.available && <Notice kind="warning" title="Unavailable">{capability.reason}</Notice>}
      <div className="workflow-content">{children}</div>
    </section>
  );
}
