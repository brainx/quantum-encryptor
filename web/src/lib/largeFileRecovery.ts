export const LARGE_FILE_RECOVERY_KEY = "quantum-encryptor.large-file-recovery.v1";

const validJobId = (value: string | null): value is string => value !== null && value.length === 32 && /^[0-9a-f]{32}$/.test(value);

export function readLargeFileRecovery(): string | null {
  try {
    const value = window.sessionStorage.getItem(LARGE_FILE_RECOVERY_KEY);
    return validJobId(value) ? value : null;
  } catch {
    return null;
  }
}

export function saveLargeFileRecovery(id: string): boolean {
  if (!validJobId(id)) return false;
  try {
    window.sessionStorage.setItem(LARGE_FILE_RECOVERY_KEY, id);
    return readLargeFileRecovery() === id;
  } catch {
    return false;
  }
}

export function removeLargeFileRecovery(id: string): void {
  try {
    // A late acknowledgement for an old job must not erase a newer locator.
    if (window.sessionStorage.getItem(LARGE_FILE_RECOVERY_KEY) === id) {
      window.sessionStorage.removeItem(LARGE_FILE_RECOVERY_KEY);
    }
  } catch {
    // The server remains authoritative; an unreadable locator expires there.
  }
}
