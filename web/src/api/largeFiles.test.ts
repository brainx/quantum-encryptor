import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchHealth } from "./client";
import { largeFileOperations, type LargeFileJob } from "./largeFiles";

vi.mock("./client", async (actual) => ({ ...await actual<typeof import("./client")>(), fetchHealth: vi.fn() }));
const job: LargeFileJob = { id: "opaque-id", mode: "encrypt", state: "awaiting_upload", phase: "upload", processedBytes: 0, totalBytes: 3, expiresAt: "2099-01-01T00:00:00Z" };
const json = (payload: unknown, status = 200) => new Response(JSON.stringify(payload), { status });

class UploadRequest {
  static last: UploadRequest;
  constructor() { UploadRequest.last = this; }
  status = 200;
  responseText = JSON.stringify({ ok: true, job: { ...job, state: "ready" } });
  withCredentials = false;
  upload: { onprogress: ((event: { loaded: number; total: number; lengthComputable: boolean }) => void) | null } = { onprogress: null };
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onabort: (() => void) | null = null;
  open = vi.fn();
  setRequestHeader = vi.fn();
  send = vi.fn();
  abort = vi.fn(() => this.onabort?.());
}

beforeEach(() => { vi.mocked(fetchHealth).mockResolvedValue({} as Awaited<ReturnType<typeof fetchHealth>>); });
afterEach(() => { vi.unstubAllGlobals(); });

describe("large file client", () => {
  it("bootstraps the cookie and reserves using metadata only", async () => {
    const fetch = vi.fn().mockResolvedValue(json({ ok: true, job }));
    vi.stubGlobal("fetch", fetch);
    const file = new File(["abc"], "report.bin");
    const signal = new AbortController().signal;
    expect(await largeFileOperations.create("encrypt", file, signal)).toEqual(job);
    expect(fetchHealth).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe("/api/jobs");
    expect(init).toMatchObject({ method: "POST", credentials: "same-origin", signal });
    expect([...init.body.entries()]).toEqual([["mode", "encrypt"], ["filename", "report.bin"], ["size", "3"]]);
  });

  it.each([403, 429, 500])("never replays a rejected reservation (%s)", async (status) => {
    const fetch = vi.fn().mockResolvedValue(json({ ok: false, error_code: "server_busy", message: "Service busy." }, status));
    vi.stubGlobal("fetch", fetch);
    await expect(largeFileOperations.create("encrypt", new File(["a"], "a"), new AbortController().signal)).rejects.toMatchObject({ status });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("uploads raw file bytes with progress and abort support", async () => {
    vi.stubGlobal("XMLHttpRequest", UploadRequest);
    const file = new File(["abc"], "report.bin");
    const progress = vi.fn();
    const controller = new AbortController();
    const pending = largeFileOperations.upload("opaque/id", file, progress, controller.signal);
    const xhr = UploadRequest.last;
    expect(xhr.open).toHaveBeenCalledWith("PUT", "/api/jobs/opaque%2Fid/upload");
    expect(xhr.withCredentials).toBe(true);
    expect(xhr.setRequestHeader).toHaveBeenCalledWith("Content-Type", "application/octet-stream");
    expect(xhr.send).toHaveBeenCalledWith(file);
    xhr.upload.onprogress?.({ loaded: 2, total: 3, lengthComputable: true });
    expect(progress).toHaveBeenCalledWith(2, 3);
    xhr.onload?.();
    await expect(pending).resolves.toMatchObject({ state: "ready" });
    controller.abort();
    expect(xhr.abort).not.toHaveBeenCalled();
  });

  it("stops the upload on abort without retrying", async () => {
    vi.stubGlobal("XMLHttpRequest", UploadRequest);
    const controller = new AbortController();
    const pending = largeFileOperations.upload(job.id, new File(["abc"], "f"), vi.fn(), controller.signal);
    controller.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(UploadRequest.last.send).toHaveBeenCalledTimes(1);
  });

  it("sends credentials only to start and protects status/cancel/clear with POST", async () => {
    const fetch = vi.fn().mockImplementation(() => Promise.resolve(json({ ok: true, job })));
    vi.stubGlobal("fetch", fetch);
    const key = new File(["PEM"], "private.pem");
    const signal = new AbortController().signal;
    await largeFileOperations.start(job.id, key, "test password", signal);
    const start = fetch.mock.calls[0];
    expect(start[0]).toBe("/api/jobs/opaque-id/start");
    expect([...start[1].body.entries()]).toEqual([["key", key], ["password", "test password"]]);
    await largeFileOperations.status(job.id, signal);
    await largeFileOperations.cancel(job.id, signal);
    await largeFileOperations.clear(job.id, signal);
    for (const [url, init] of fetch.mock.calls.slice(1)) {
      expect(url).toMatch(/\/(status|cancel|clear)$/);
      expect(init).toEqual({ method: "POST", credentials: "same-origin", signal,
        ...(url.endsWith("/status") ? {} : { keepalive: true }) });
    }
  });

  it("returns job_expired and rejects malformed job snapshots", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json({ error_code: "job_expired", message: "Expired" }, 410))
      .mockResolvedValueOnce(json({ ok: true, job: { ...job, processedBytes: 4 } }));
    vi.stubGlobal("fetch", fetch);
    await expect(largeFileOperations.status(job.id)).rejects.toMatchObject({ status: 410, code: "job_expired" });
    await expect(largeFileOperations.status(job.id)).rejects.toMatchObject({ code: "invalid_job" });
  });

  it("requests a download with a temporary POST form and no credential fields or blob fetch", () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    let submitted: HTMLFormElement | null = null;
    vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(function (this: HTMLFormElement) { submitted = this; });
    largeFileOperations.download("opaque/id");
    expect(submitted).not.toBeNull();
    expect(submitted!.getAttribute("action")).toBe("/api/jobs/opaque%2Fid/download");
    expect(submitted!.method).toBe("post");
    expect(submitted!.target).toBe("_blank");
    expect(submitted!.rel).toBe("noopener");
    expect(submitted!.elements).toHaveLength(0);
    expect(document.querySelector("form")).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});
