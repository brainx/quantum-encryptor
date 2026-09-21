import { ApiError, fetchHealth } from "./client";
import type { FileVerification } from "./contracts";

export type LargeFileMode = "encrypt" | "decrypt" | "verify";
export type LargeFileState = "awaiting_upload" | "uploading" | "ready" | "running" | "cancelling" | "complete" | "failed" | "cancelled";
export type LargeFileJob = {
  id: string;
  mode: LargeFileMode;
  state: LargeFileState;
  phase: string;
  processedBytes: number;
  totalBytes: number;
  expiresAt: string;
  result?: { filename: string; bytes: number };
  verification?: FileVerification;
  error?: { code: string; message: string };
};
export type LargeFileOperations = {
  create: (mode: LargeFileMode, file: File, signal: AbortSignal) => Promise<LargeFileJob>;
  upload: (id: string, file: File, progress: (loaded: number, total: number) => void, signal: AbortSignal) => Promise<LargeFileJob>;
  start: (id: string, key: File, password: string, signal: AbortSignal) => Promise<LargeFileJob>;
  status: (id: string, signal?: AbortSignal) => Promise<LargeFileJob>;
  cancel: (id: string, signal?: AbortSignal) => Promise<LargeFileJob>;
  clear: (id: string, signal?: AbortSignal) => Promise<unknown>;
  download: (id: string) => void;
};

const states = new Set<LargeFileState>(["awaiting_upload", "uploading", "ready", "running", "cancelling", "complete", "failed", "cancelled"]);
const modes = new Set<LargeFileMode>(["encrypt", "decrypt", "verify"]);

function jobPayload(payload: { job?: LargeFileJob; ok?: boolean }): LargeFileJob {
  const job = payload?.job;
  if (!payload?.ok || !job || typeof job.id !== "string" || !job.id || !modes.has(job.mode) || !states.has(job.state) ||
      typeof job.phase !== "string" || !Number.isSafeInteger(job.processedBytes) || job.processedBytes < 0 ||
      !Number.isSafeInteger(job.totalBytes) || job.totalBytes < 0 || job.processedBytes > job.totalBytes ||
      typeof job.expiresAt !== "string" || !Number.isFinite(Date.parse(job.expiresAt))) {
    throw new ApiError(502, "invalid_job", "The local service returned an invalid job status.");
  }
  return job;
}

async function parseResponse(response: Response): Promise<unknown> {
  let payload: { error_code?: string; message?: string };
  try { payload = await response.json(); }
  catch { throw new ApiError(response.status || 502, "api_error", "The local service returned an invalid response."); }
  if (!response.ok) throw new ApiError(response.status, payload.error_code || "api_error", payload.message || "Request failed.");
  return payload;
}

function jobUrl(id: string, action: string): string {
  return `/api/jobs/${encodeURIComponent(id)}/${action}`;
}

async function postJob(id: string, action: string, signal?: AbortSignal): Promise<LargeFileJob> {
  const response = await fetch(jobUrl(id, action), {
    method: "POST", credentials: "same-origin", signal, ...(action === "cancel" ? { keepalive: true } : {})
  });
  return jobPayload(await parseResponse(response) as { job: LargeFileJob; ok: boolean });
}

export const largeFileOperations: LargeFileOperations = {
  async create(mode, file, signal) {
    // Establish the HttpOnly cookie before admission. Sensitive requests are never replayed.
    await fetchHealth();
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const form = new FormData();
    form.append("mode", mode);
    form.append("filename", file.name);
    form.append("size", String(file.size));
    const response = await fetch("/api/jobs", { method: "POST", body: form, credentials: "same-origin", signal });
    return jobPayload(await parseResponse(response) as { job: LargeFileJob; ok: boolean });
  },
  upload(id, file, progress, signal) {
    return new Promise((resolve, reject) => {
      if (signal.aborted) { reject(new DOMException("Aborted", "AbortError")); return; }
      const xhr = new XMLHttpRequest();
      const abort = () => xhr.abort();
      const finish = () => { signal.removeEventListener("abort", abort); };
      xhr.open("PUT", jobUrl(id, "upload"));
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) progress(Math.min(event.loaded, file.size), file.size);
      };
      xhr.onload = () => {
        finish();
        try {
          const payload = JSON.parse(xhr.responseText);
          if (xhr.status < 200 || xhr.status >= 300) throw new ApiError(xhr.status, payload.error_code || "api_error", payload.message || "Upload failed.");
          resolve(jobPayload(payload));
        } catch (error) {
          reject(error instanceof ApiError ? error : new ApiError(xhr.status || 502, "api_error", "The local service returned an invalid upload response."));
        }
      };
      xhr.onerror = () => { finish(); reject(new TypeError("Upload connection failed")); };
      xhr.onabort = () => { finish(); reject(new DOMException("Aborted", "AbortError")); };
      signal.addEventListener("abort", abort, { once: true });
      try { xhr.send(file); } catch (error) { finish(); reject(error); }
    });
  },
  async start(id, key, password, signal) {
    const form = new FormData();
    form.append("key", key);
    form.append("password", password);
    const response = await fetch(jobUrl(id, "start"), { method: "POST", body: form, credentials: "same-origin", signal });
    return jobPayload(await parseResponse(response) as { job: LargeFileJob; ok: boolean });
  },
  status: (id, signal) => postJob(id, "status", signal),
  cancel: (id, signal) => postJob(id, "cancel", signal),
  async clear(id, signal) {
    const response = await fetch(jobUrl(id, "clear"), { method: "POST", credentials: "same-origin", signal, keepalive: true });
    return parseResponse(response);
  },
  download(id) {
    const form = document.createElement("form");
    form.method = "POST";
    form.action = jobUrl(id, "download");
    form.target = "_blank";
    form.rel = "noopener";
    form.hidden = true;
    document.body.appendChild(form);
    try { form.submit(); } finally { form.remove(); }
  }
};
