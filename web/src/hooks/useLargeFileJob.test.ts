import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { LargeFileJob, LargeFileOperations } from "../api/largeFiles";
import { useLargeFileJob } from "./useLargeFileJob";

function snapshot(patch: Partial<LargeFileJob> = {}): LargeFileJob {
  return { id: "job-one", mode: "encrypt", state: "running", phase: "encrypting", processedBytes: 0, totalBytes: 3,
    expiresAt: new Date(Date.now() + 60_000).toISOString(), ...patch };
}
function operations(): LargeFileOperations {
  return { create: vi.fn().mockResolvedValue(snapshot({ state: "awaiting_upload" })), upload: vi.fn().mockResolvedValue(snapshot({ state: "ready" })),
    start: vi.fn().mockResolvedValue(snapshot()), status: vi.fn().mockResolvedValue(snapshot()), cancel: vi.fn().mockResolvedValue(snapshot({ state: "cancelled" })),
    clear: vi.fn().mockResolvedValue({ ok: true }), download: vi.fn() };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}
const file = new File(["abc"], "report.txt");
const key = new File(["PEM"], "public.pem");
afterEach(() => { vi.useRealTimers(); });

describe("useLargeFileJob", () => {
  it("requests cleanup on pagehide and does not repeat it on unmount", async () => {
    const api = operations();
    const { result, unmount } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    act(() => { window.dispatchEvent(new Event("pagehide")); });
    expect(api.cancel).toHaveBeenCalledWith("job-one");
    expect(result.current.restoring).toBe(true);
    unmount();
    expect(api.cancel).toHaveBeenCalledTimes(1);
  });

  it("revalidates a cached page instead of reusing a result cleared on pagehide", async () => {
    const api = operations();
    vi.mocked(api.start).mockResolvedValue(snapshot({ state: "complete", result: { filename: "result.pqc", bytes: 10 } }));
    const status = deferred<LargeFileJob>();
    vi.mocked(api.status).mockReturnValue(status.promise);
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    act(() => { window.dispatchEvent(new Event("pagehide")); });
    expect(api.clear).toHaveBeenCalledWith("job-one");
    await act(async () => { window.dispatchEvent(new Event("pageshow")); });
    expect(api.status).toHaveBeenCalledWith("job-one", expect.any(AbortSignal));
    expect(result.current.restoring).toBe(true);
    await act(async () => { status.resolve(snapshot({ state: "cancelled" })); });
    expect(result.current.restoring).toBe(false);
    expect(result.current.job?.state).toBe("cancelled");
  });

  it("waits for pagehide cleanup before checking a restored result", async () => {
    const api = operations();
    vi.mocked(api.start).mockResolvedValue(snapshot({ state: "complete", result: { filename: "result.pqc", bytes: 10 } }));
    const cleanup = deferred<unknown>();
    vi.mocked(api.clear).mockReturnValue(cleanup.promise);
    vi.mocked(api.status).mockRejectedValue(new ApiError(410, "job_expired", "Expired"));
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    await act(async () => {
      window.dispatchEvent(new Event("pagehide"));
      window.dispatchEvent(new Event("pageshow"));
    });
    expect(result.current.restoring).toBe(true);
    expect(api.status).not.toHaveBeenCalled();
    await act(async () => { cleanup.resolve({ ok: true }); });
    expect(api.status).toHaveBeenCalledTimes(1);
    expect(result.current.job).toBeNull();
    expect(result.current.restoring).toBe(false);
  });

  it("restores after an in-flight user cancellation finishes", async () => {
    const api = operations();
    const cancellation = deferred<LargeFileJob>();
    vi.mocked(api.cancel).mockReturnValueOnce(cancellation.promise);
    vi.mocked(api.status).mockResolvedValue(snapshot({ state: "cancelled" }));
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    let pending!: Promise<void>;
    act(() => { pending = result.current.cancel(); });
    await act(async () => {
      window.dispatchEvent(new Event("pagehide"));
      window.dispatchEvent(new Event("pageshow"));
    });
    expect(api.status).not.toHaveBeenCalled();
    expect(result.current.restoring).toBe(true);
    await act(async () => { cancellation.resolve(snapshot({ state: "cancelled" })); await pending; });
    expect(result.current.restoring).toBe(false);
    expect(result.current.job?.state).toBe("cancelled");
  });

  it("restores without getting stuck when an in-flight user clear removes the job", async () => {
    const api = operations();
    vi.mocked(api.start).mockResolvedValue(snapshot({ state: "complete", result: { filename: "result.pqc", bytes: 10 } }));
    const cleanup = deferred<unknown>();
    vi.mocked(api.clear).mockReturnValue(cleanup.promise);
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    let pending!: Promise<boolean>;
    act(() => { pending = result.current.clear(); });
    await act(async () => {
      window.dispatchEvent(new Event("pagehide"));
      window.dispatchEvent(new Event("pageshow"));
    });
    expect(result.current.restoring).toBe(true);
    await act(async () => { cleanup.resolve({ ok: true }); await pending; });
    expect(result.current.restoring).toBe(false);
    expect(result.current.stage).toBeNull();
    expect(result.current.job).toBeNull();
    expect(api.clear).toHaveBeenCalledTimes(1);
  });

  it("unlocks after a rejected reservation without automatically retrying", async () => {
    const api = operations();
    vi.mocked(api.create).mockRejectedValue(new ApiError(429, "server_busy", "Another operation is running."));
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    expect(result.current.stage).toBeNull();
    expect(result.current.job).toBeNull();
    expect(result.current.error).toBe("Another operation is running.");
    expect(api.create).toHaveBeenCalledTimes(1);
    expect(api.upload).not.toHaveBeenCalled();
  });

  it("keeps cancellation visible while the aborted upload settles before server cleanup", async () => {
    const api = operations();
    vi.mocked(api.upload).mockImplementation((_id, _file, _progress, signal) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    }));
    const cancellation = deferred<LargeFileJob>();
    vi.mocked(api.cancel).mockReturnValue(cancellation.promise);
    const { result } = renderHook(() => useLargeFileJob(api));
    let running!: Promise<void>;
    act(() => { running = result.current.start("encrypt", file, key, ""); });
    await waitFor(() => expect(result.current.stage).toBe("uploading"));
    let cancelling!: Promise<void>;
    await act(async () => { cancelling = result.current.cancel(); await running; });
    expect(result.current.stage).toBe("cancelling");
    await act(async () => { cancellation.resolve(snapshot({ state: "cancelled" })); await cancelling; });
    expect(result.current.stage).toBeNull();
    expect(result.current.job?.state).toBe("cancelled");
    expect(api.start).not.toHaveBeenCalled();
  });

  it("serializes reserve/upload/start, exposes byte progress, and never starts twice", async () => {
    const api = operations();
    const upload = deferred<LargeFileJob>();
    vi.mocked(api.upload).mockReturnValue(upload.promise);
    const { result } = renderHook(() => useLargeFileJob(api));
    let running!: Promise<void>;
    act(() => { running = result.current.start("encrypt", file, key, ""); });
    await waitFor(() => expect(result.current.stage).toBe("uploading"));
    act(() => vi.mocked(api.upload).mock.calls[0][2](2, 3));
    expect(result.current.uploadBytes).toBe(2);
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    expect(api.create).toHaveBeenCalledTimes(1);
    expect(api.start).not.toHaveBeenCalled();
    await act(async () => { upload.resolve(snapshot({ state: "ready" })); await running; });
    expect(api.start).toHaveBeenCalledWith("job-one", key, "", expect.any(AbortSignal));
    expect(result.current.job?.state).toBe("running");
  });

  it("keeps cancellation pending until the server confirms it and suppresses late start output", async () => {
    const api = operations();
    const start = deferred<LargeFileJob>();
    vi.mocked(api.start).mockReturnValue(start.promise);
    vi.mocked(api.cancel).mockResolvedValue(snapshot({ state: "cancelling" }));
    const { result } = renderHook(() => useLargeFileJob(api));
    let running!: Promise<void>;
    act(() => { running = result.current.start("encrypt", file, key, ""); });
    await waitFor(() => expect(api.start).toHaveBeenCalled());
    await act(async () => { await result.current.cancel(); });
    expect(result.current.job?.state).toBe("cancelling");
    expect(vi.mocked(api.start).mock.calls[0][3].aborted).toBe(true);
    await act(async () => { start.resolve(snapshot({ state: "complete", result: { filename: "report.txt.pqc", bytes: 30 } })); await running; });
    expect(result.current.job?.state).toBe("cancelling");
    vi.mocked(api.status).mockResolvedValue(snapshot({ state: "cancelled" }));
    await act(async () => { await result.current.refresh(); });
    expect(result.current.job?.state).toBe("cancelled");
  });

  it("cancels a reservation returned after cancellation without uploading", async () => {
    const api = operations();
    const reservation = deferred<LargeFileJob>();
    vi.mocked(api.create).mockReturnValue(reservation.promise);
    const { result } = renderHook(() => useLargeFileJob(api));
    let running!: Promise<void>;
    act(() => { running = result.current.start("encrypt", file, key, ""); });
    await act(async () => { await result.current.cancel(); });
    await act(async () => { reservation.resolve(snapshot({ state: "awaiting_upload" })); await running; });
    expect(api.cancel).toHaveBeenCalledWith("job-one");
    expect(api.upload).not.toHaveBeenCalled();
    expect(result.current.job?.state).toBe("cancelled");
  });

  it("retains a late reservation when cancellation fails so cleanup can be retried", async () => {
    const api = operations();
    const reservation = deferred<LargeFileJob>();
    vi.mocked(api.create).mockReturnValue(reservation.promise);
    vi.mocked(api.cancel).mockRejectedValue(new TypeError("offline"));
    const { result } = renderHook(() => useLargeFileJob(api));
    let running!: Promise<void>;
    act(() => { running = result.current.start("encrypt", file, key, ""); });
    await act(async () => { await result.current.cancel(); });
    await act(async () => { reservation.resolve(snapshot({ state: "awaiting_upload" })); await running; });
    expect(result.current.job?.id).toBe("job-one");
    expect(result.current.pollingPaused).toBe(true);
    expect(result.current.error).toContain("Could not reach the local service");
    expect(api.upload).not.toHaveBeenCalled();
  });

  it("suppresses stale status responses after cancellation", async () => {
    const api = operations();
    const status = deferred<LargeFileJob>();
    vi.mocked(api.status).mockReturnValue(status.promise);
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    let refresh!: Promise<void>;
    act(() => { refresh = result.current.refresh(); });
    await act(async () => { await result.current.cancel(); });
    await act(async () => { status.resolve(snapshot()); await refresh; });
    expect(result.current.job?.state).toBe("cancelled");
  });

  it("polls serially, pauses on a connection error, and retries only status", async () => {
    vi.useFakeTimers();
    const api = operations();
    const first = deferred<LargeFileJob>();
    vi.mocked(api.status).mockReturnValueOnce(first.promise).mockRejectedValueOnce(new TypeError("private transport detail"));
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(api.status).toHaveBeenCalledTimes(1);
    await act(async () => { first.resolve(snapshot({ processedBytes: 1 })); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(result.current.pollingPaused).toBe(true);
    expect(result.current.job?.id).toBe("job-one");
    expect(result.current.error).toContain("Could not reach the local service");
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    expect(api.status).toHaveBeenCalledTimes(2);
    vi.mocked(api.status).mockResolvedValue(snapshot({ state: "complete", result: { filename: "result.pqc", bytes: 10 } }));
    await act(async () => { await result.current.refresh(); });
    expect(result.current.pollingPaused).toBe(false);
    expect(result.current.job?.state).toBe("complete");
    expect(api.create).toHaveBeenCalledTimes(1);
    expect(api.start).toHaveBeenCalledTimes(1);
  });

  it("retains a known job after an uncertain upload failure without replaying it", async () => {
    const api = operations();
    vi.mocked(api.upload).mockRejectedValue(new TypeError("lost upload response"));
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    expect(result.current.job?.id).toBe("job-one");
    expect(result.current.pollingPaused).toBe(true);
    expect(api.upload).toHaveBeenCalledTimes(1);
    expect(api.start).not.toHaveBeenCalled();
  });

  it("removes an expired job and allows a fresh explicit operation", async () => {
    const api = operations();
    vi.mocked(api.status).mockRejectedValue(new ApiError(410, "job_expired", "Expired"));
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); await result.current.refresh(); });
    expect(result.current.job).toBeNull();
    expect(result.current.expired).toBe(true);
    expect(result.current.error).toContain("temporary job has expired");
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    expect(api.create).toHaveBeenCalledTimes(2);
  });

  it("keeps a completed job until cleanup succeeds", async () => {
    const api = operations();
    vi.mocked(api.start).mockResolvedValue(snapshot({ state: "complete", result: { filename: "result.pqc", bytes: 10 } }));
    vi.mocked(api.clear).mockRejectedValueOnce(new TypeError("offline")).mockResolvedValueOnce({ ok: true });
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    await act(async () => { expect(await result.current.clear()).toBe(false); });
    expect(result.current.job?.state).toBe("complete");
    await act(async () => { expect(await result.current.clear()).toBe(true); });
    expect(result.current.job).toBeNull();
  });

  it("requires cancellation to finish before clearing a running job", async () => {
    const api = operations();
    const { result } = renderHook(() => useLargeFileJob(api));
    await act(async () => { await result.current.start("encrypt", file, key, ""); });
    await act(async () => { expect(await result.current.clear()).toBe(false); });
    expect(api.clear).not.toHaveBeenCalled();
    await act(async () => { await result.current.cancel(); });
    await act(async () => { expect(await result.current.clear()).toBe(true); });
    expect(api.clear).toHaveBeenCalledWith("job-one");
  });

  it("aborts on unmount, requests server cleanup, and suppresses late work", async () => {
    const api = operations();
    const upload = deferred<LargeFileJob>();
    vi.mocked(api.upload).mockReturnValue(upload.promise);
    const { result, unmount } = renderHook(() => useLargeFileJob(api));
    let running!: Promise<void>;
    act(() => { running = result.current.start("encrypt", file, key, ""); });
    await waitFor(() => expect(api.upload).toHaveBeenCalled());
    unmount();
    expect(vi.mocked(api.upload).mock.calls[0][3].aborted).toBe(true);
    expect(api.cancel).toHaveBeenCalledWith("job-one");
    await act(async () => { upload.resolve(snapshot({ state: "ready" })); await running; });
    expect(api.start).not.toHaveBeenCalled();
  });
});
