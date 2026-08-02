export type WorkflowPhase = "select" | "review" | "complete";

export function deriveWorkflowPhase(state: { ready: boolean; complete: boolean }): WorkflowPhase {
  if (state.complete) return "complete";
  return state.ready ? "review" : "select";
}
