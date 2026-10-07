import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LARGE_FILE_RECOVERY_KEY, readLargeFileRecovery, removeLargeFileRecovery, saveLargeFileRecovery } from "./largeFileRecovery";

const id = "0123456789abcdef0123456789abcdef";
beforeEach(() => { sessionStorage.clear(); localStorage.clear(); });
afterEach(() => { vi.restoreAllMocks(); sessionStorage.clear(); });

describe("large-file recovery storage", () => {
  it("stores only a canonical opaque ID in this tab's session storage", () => {
    expect(readLargeFileRecovery()).toBeNull();
    expect(saveLargeFileRecovery(id)).toBe(true);
    expect(readLargeFileRecovery()).toBe(id);
    expect(Object.entries(sessionStorage)).toEqual([[LARGE_FILE_RECOVERY_KEY, id]]);
    expect(localStorage.length).toBe(0);
  });

  it.each(["", "job-one", id.toUpperCase(), `${id}\n`, ` ${id}`, `${id}/status`, JSON.stringify({ id }), "a".repeat(33)])(
    "ignores malformed locators without using them: %j", (value) => {
      sessionStorage.setItem(LARGE_FILE_RECOVERY_KEY, value);
      expect(readLargeFileRecovery()).toBeNull();
      expect(saveLargeFileRecovery(value)).toBe(false);
    });

  it("removes only the job whose cleanup was acknowledged", () => {
    const newer = "f".repeat(32);
    saveLargeFileRecovery(newer);
    removeLargeFileRecovery(id);
    expect(readLargeFileRecovery()).toBe(newer);
    removeLargeFileRecovery(newer);
    expect(readLargeFileRecovery()).toBeNull();
  });

  it("handles blocked reads and writes without claiming recovery is available", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new DOMException("Blocked", "SecurityError"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Blocked", "QuotaExceededError"); });
    expect(readLargeFileRecovery()).toBeNull();
    expect(saveLargeFileRecovery(id)).toBe(false);
    expect(() => removeLargeFileRecovery(id)).not.toThrow();
  });
});
