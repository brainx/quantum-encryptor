export function isPublicKeyFingerprint(value: unknown): value is string {
  return typeof value === "string" && value.length === "QE1-SHA3-256:".length + 64 &&
    /^QE1-SHA3-256:[0-9a-f]{64}$/.test(value);
}

export function recipientFingerprintError(expected: string, actual: string | null | undefined, supported: boolean): string | null {
  const fingerprint = expected.trim();
  if (!fingerprint) return null;
  if (!isPublicKeyFingerprint(fingerprint)) {
    return "Enter the complete fingerprint: QE1-SHA3-256: followed by 64 lowercase hexadecimal characters.";
  }
  if (!supported) return "Restart an updated local service to enforce the expected recipient fingerprint.";
  if (actual && fingerprint !== actual) return "The expected fingerprint does not match the selected public key. Check the key and trusted fingerprint before encrypting.";
  return null;
}
