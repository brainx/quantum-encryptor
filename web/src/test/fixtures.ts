import type { Health } from "../api/contracts";

export const READY_HEALTH: Health = {
  ok: true,
  backendReady: true,
  backendMessage: "Post-quantum backend ready.",
  capabilities: {
    inspect: { available: true, reason: "" },
    generate: { available: true, reason: "" },
    encrypt: { available: true, reason: "" },
    decrypt: { available: true, reason: "" }
  },
  formatVersion: 4,
  kem: "ML-KEM-768+X25519-v2",
  kemComponent: "ML-KEM-768",
  configuredKem: "ML-KEM-768",
  dem: "AES-256-GCM",
  maxFileBytes: 104857600,
  maxEncryptedFileBytes: 105906314,
  maxPemBytes: 131072,
  apiToken: "test-local-token",
  passwordPolicy: {
    minChars: 16,
    minUniqueChars: 5
  }
};
