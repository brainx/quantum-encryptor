export type Health = {
  ok: boolean;
  backendReady: boolean;
  backendMessage: string;
  formatVersion: number;
  kem: string;
  configuredKem: string;
  dem: string;
  maxFileBytes: number;
  maxEncryptedFileBytes: number;
  maxPemBytes: number;
  apiToken: string;
  passwordPolicy: {
    minChars: number;
    minUniqueChars: number;
  };
};

export type KeyInspectResult = {
  ok: boolean;
  keyInfo: {
    kem: string;
    key_type: "public" | "private";
    private_key_encrypted?: boolean;
    private_key_format_version?: number;
    private_key_kdf?: string;
  };
  display: Record<string, string>;
};

export type GeneratedKeys = {
  ok: boolean;
  kem: string;
  publicPem: string;
  privatePem: string;
  publicFilename: string;
  privateFilename: string;
};

export type DownloadResult = {
  blob: Blob;
  filename: string;
};

type ApiErrorPayload = {
  ok: false;
  error_code: string;
  message: string;
};

let localApiToken = "";
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

async function apiTokenHeaders(): Promise<HeadersInit> {
  if (!localApiToken) {
    await fetchHealth();
  }
  if (!localApiToken) {
    throw new ApiError(503, "missing_api_token", "Local API token is not available.");
  }
  return { "X-Quantum-Encryptor-Token": localApiToken };
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
        const payload = (await response.json()) as Health;
        localApiToken = payload.apiToken;
        return payload;
      })
      .finally(() => {
        healthRequest = null;
      });
  }
  return healthRequest;
}

export async function inspectKey(file: File): Promise<KeyInspectResult> {
  const form = new FormData();
  form.append("key", file);
  const response = await fetch("/api/keys/inspect", { method: "POST", body: form, headers: await apiTokenHeaders() });
  if (!response.ok) await parseError(response);
  return (await response.json()) as KeyInspectResult;
}

export async function generateKeys(password: string): Promise<GeneratedKeys> {
  const form = new FormData();
  form.append("password", password);
  const response = await fetch("/api/keys/generate", { method: "POST", body: form, headers: await apiTokenHeaders() });
  if (!response.ok) await parseError(response);
  return (await response.json()) as GeneratedKeys;
}

export async function encryptFile(file: File, publicKey: File, outputFilename: string): Promise<DownloadResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("public_key", publicKey);
  form.append("output_filename", outputFilename);
  const response = await fetch("/api/files/encrypt", { method: "POST", body: form, headers: await apiTokenHeaders() });
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
  outputFilename: string
): Promise<DownloadResult> {
  const form = new FormData();
  form.append("file", file);
  form.append("private_key", privateKey);
  form.append("password", password);
  form.append("output_filename", outputFilename);
  const response = await fetch("/api/files/decrypt", { method: "POST", body: form, headers: await apiTokenHeaders() });
  if (!response.ok) await parseError(response);
  return {
    blob: await response.blob(),
    filename: filenameFromDisposition(response.headers.get("Content-Disposition"), outputFilename)
  };
}
