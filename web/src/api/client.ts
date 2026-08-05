import type { DownloadResult, GeneratedKeys, Health, KeyInspectResult } from "./contracts";

type ApiErrorPayload = {
  ok: false;
  error_code: string;
  message: string;
};

let healthLoaded = false;
let healthRequest: Promise<Health> | null = null;

export class ApiError extends Error {
  code: string;
  status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function rejectedApiToken(response: Response): Promise<boolean> {
  if (response.status !== 403) return false;
  try {
    const payload = (await response.clone().json()) as Partial<ApiErrorPayload>;
    return payload.error_code === "missing_api_token";
  } catch {
    return false;
  }
}

async function ensureHealth(): Promise<void> {
  // The first health fetch sets the per-process HttpOnly auth cookie; the browser
  // attaches it to same-origin state-changing requests automatically.
  if (!healthLoaded) {
    await fetchHealth();
    healthLoaded = true;
  }
}

async function fetchStateChanging(input: RequestInfo | URL, init: RequestInit): Promise<Response> {
  await ensureHealth();
  let response = await fetch(input, init);
  if (await rejectedApiToken(response)) {
    // The per-process token rotates on server restart; renew the auth cookie and retry once.
    await fetchHealth();
    response = await fetch(input, init);
  }
  return response;
}

function filenameFromDisposition(disposition: string | null, fallback: string): string {
  if (!disposition) return fallback;
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) return decodeURIComponent(utf8Match[1].replace(/"/g, ""));
  const asciiMatch = disposition.match(/filename="([^"]+)"/i);
  if (asciiMatch?.[1]) return asciiMatch[1];
  return fallback;
}

async function parseError(response: Response): Promise<never> {
  try {
    const payload = (await response.json()) as ApiErrorPayload;
    throw new ApiError(response.status, payload.error_code || "api_error", payload.message || "Request failed.");
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(response.status, "api_error", "Request failed.");
  }
}

export async function fetchHealth(): Promise<Health> {
  if (!healthRequest) {
    healthRequest = fetch("/api/health")
      .then(async (response) => {
        if (!response.ok) await parseError(response);
        return (await response.json()) as Health;
      })
      .finally(() => {
        healthRequest = null;
      });
  }
  return healthRequest;
}

export async function inspectKey(file: File, signal?: AbortSignal): Promise<KeyInspectResult> {
  const form = new FormData();
  form.append("key", file);
  const response = await fetchStateChanging("/api/keys/inspect", {
    method: "POST",
    body: form,
    signal
  });
  if (!response.ok) await parseError(response);
  return (await response.json()) as KeyInspectResult;
}

export async function generateKeys(password: string, signal?: AbortSignal): Promise<GeneratedKeys> {
  const form = new FormData();
  form.append("password", password);
  const response = await fetchStateChanging("/api/keys/generate", { method: "POST", body: form, signal });
  if (!response.ok) await parseError(response);
  return (await response.json()) as GeneratedKeys;
}

export async function encryptFile(
  file: File,
  publicKey: File,
  outputFilename: string,
  signal?: AbortSignal
): Promise<DownloadResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("public_key", publicKey);
  form.append("output_filename", outputFilename);
  const response = await fetchStateChanging("/api/files/encrypt", { method: "POST", body: form, signal });
  if (!response.ok) await parseError(response);
  return {
    blob: await response.blob(),
    filename: filenameFromDisposition(response.headers.get("Content-Disposition"), outputFilename)
  };
}

export async function decryptFile(
  file: File,
  privateKey: File,
  password: string,
  outputFilename: string,
  signal?: AbortSignal
): Promise<DownloadResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("private_key", privateKey);
  form.append("password", password);
  form.append("output_filename", outputFilename);
  const response = await fetchStateChanging("/api/files/decrypt", { method: "POST", body: form, signal });
  if (!response.ok) await parseError(response);
  return {
    blob: await response.blob(),
    filename: filenameFromDisposition(response.headers.get("Content-Disposition"), outputFilename)
  };
}
