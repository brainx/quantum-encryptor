import { describe, expect, it } from "vitest";
import { deriveWorkflowPhase } from "./workflow";

describe("deriveWorkflowPhase", () => {
  it("does not report review before all inputs are ready", () => {
    expect(deriveWorkflowPhase({ ready: false, complete: false })).toBe("select");
  });

  it("reports review only for ready inputs", () => {
    expect(deriveWorkflowPhase({ ready: true, complete: false })).toBe("review");
  });

  it("prioritizes a completed result", () => {
    expect(deriveWorkflowPhase({ ready: true, complete: true })).toBe("complete");
  });
});
