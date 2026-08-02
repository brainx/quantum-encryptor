import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { InspectKeyOperation, KeyInspectResult } from "../api";
import { useKeyInspection } from "./useKeyInspection";

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
};

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function result(kem: string): KeyInspectResult {
  return {
    ok: true,
    keyInfo: { kem, key_type: "public" },
    display: { Algorithm: kem }
  };
}

function InspectionProbe({ file, inspect }: { file: File | null; inspect: InspectKeyOperation }) {
  const state = useKeyInspection(file, 1024, inspect);
  return (
    <output data-testid="inspection-state">
      {state.result?.keyInfo.kem ?? "no result"}|{state.error ?? "no error"}|{state.loading ? "loading" : "idle"}
    </output>
  );
}

describe("useKeyInspection", () => {
  it("aborts the previous request when the selected file changes", () => {
    const firstFile = new File(["first"], "first.pem", { type: "application/x-pem-file" });
    const secondFile = new File(["second"], "second.pem", { type: "application/x-pem-file" });
    let firstSignal: AbortSignal | undefined;
    const inspect = vi.fn((file: File, signal?: AbortSignal) => {
      if (file === firstFile) firstSignal = signal;
      return new Promise<never>(() => undefined);
    });

    const { rerender } = render(<InspectionProbe file={firstFile} inspect={inspect} />);
    expect(screen.getByTestId("inspection-state")).toHaveTextContent("loading");

    rerender(<InspectionProbe file={secondFile} inspect={inspect} />);

    expect(firstSignal?.aborted).toBe(true);
    expect(inspect).toHaveBeenCalledWith(secondFile, expect.any(AbortSignal));
  });

  it("does not render a completed result for a newly selected file", async () => {
    const firstFile = new File(["first"], "first.pem", { type: "application/x-pem-file" });
    const secondFile = new File(["second"], "second.pem", { type: "application/x-pem-file" });
    const firstRequest = deferred<KeyInspectResult>();
    const secondRequest = deferred<KeyInspectResult>();
    const inspect = vi.fn((file: File) => (file === firstFile ? firstRequest.promise : secondRequest.promise));
    const { rerender } = render(<InspectionProbe file={firstFile} inspect={inspect} />);

    await act(async () => {
      firstRequest.resolve(result("first-result"));
      await firstRequest.promise;
    });
    expect(screen.getByTestId("inspection-state")).toHaveTextContent("first-result");

    rerender(<InspectionProbe file={secondFile} inspect={inspect} />);

    expect(screen.getByTestId("inspection-state")).not.toHaveTextContent("first-result");
    expect(screen.getByTestId("inspection-state")).toHaveTextContent("loading");
  });

  it("ignores a previous request resolving after selection changes", async () => {
    const firstFile = new File(["first"], "first.pem", { type: "application/x-pem-file" });
    const secondFile = new File(["second"], "second.pem", { type: "application/x-pem-file" });
    const firstRequest = deferred<KeyInspectResult>();
    const secondRequest = deferred<KeyInspectResult>();
    const inspect = vi.fn((file: File) => (file === firstFile ? firstRequest.promise : secondRequest.promise));
    const { rerender } = render(<InspectionProbe file={firstFile} inspect={inspect} />);

    rerender(<InspectionProbe file={secondFile} inspect={inspect} />);
    await act(async () => {
      firstRequest.resolve(result("first-result"));
      await firstRequest.promise;
    });

    expect(screen.getByTestId("inspection-state")).not.toHaveTextContent("first-result");
    await act(async () => {
      secondRequest.resolve(result("second-result"));
      await secondRequest.promise;
    });
    expect(screen.getByTestId("inspection-state")).toHaveTextContent("second-result");
  });

  it("ignores a previous request rejecting after selection changes", async () => {
    const firstFile = new File(["first"], "first.pem", { type: "application/x-pem-file" });
    const secondFile = new File(["second"], "second.pem", { type: "application/x-pem-file" });
    const firstRequest = deferred<KeyInspectResult>();
    const secondRequest = deferred<KeyInspectResult>();
    const inspect = vi.fn((file: File) => (file === firstFile ? firstRequest.promise : secondRequest.promise));
    const { rerender } = render(<InspectionProbe file={firstFile} inspect={inspect} />);

    rerender(<InspectionProbe file={secondFile} inspect={inspect} />);
    await act(async () => {
      firstRequest.reject(new Error("first error"));
      await Promise.resolve();
    });

    expect(screen.getByTestId("inspection-state")).not.toHaveTextContent("first error");
    await act(async () => {
      secondRequest.resolve(result("second-result"));
      await secondRequest.promise;
    });
    expect(screen.getByTestId("inspection-state")).toHaveTextContent("second-result");
  });

  it("rejects an oversized key locally without calling the API", async () => {
    const inspect = vi.fn();
    const oversizedFile = new File([new Uint8Array(1025)], "oversized.pem", { type: "application/x-pem-file" });

    render(<InspectionProbe file={oversizedFile} inspect={inspect} />);

    expect(await screen.findByText(/exceeds the 1,024 byte limit/)).toBeVisible();
    expect(inspect).not.toHaveBeenCalled();
  });
});
