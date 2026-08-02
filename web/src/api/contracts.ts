export type CapabilityName = "inspect" | "generate" | "encrypt" | "decrypt";

export type Capability = {
  available: boolean;
  reason: string;
};

export type Health = {
  ok: boolean;
  backendReady: boolean;
  backendMessage: string;
  capabilities: Record<CapabilityName, Capability>;
  formatVersion: number;
  kem: string;
  kemComponent: string;
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

export type InspectKeyOperation = (file: File, signal?: AbortSignal) => Promise<KeyInspectResult>;
export type GenerateKeysOperation = (password: string, signal?: AbortSignal) => Promise<GeneratedKeys>;
export type EncryptFileOperation = (
  file: File,
  publicKey: File,
  outputFilename: string,
  signal?: AbortSignal
) => Promise<DownloadResult>;
export type DecryptFileOperation = (
  file: File,
  privateKey: File,
  password: string,
  outputFilename: string,
  signal?: AbortSignal
) => Promise<DownloadResult>;
