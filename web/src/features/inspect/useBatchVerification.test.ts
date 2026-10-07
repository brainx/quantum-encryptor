import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type FileVerification, type VerifyFileOperation } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { batchVerificationReport, useBatchVerification } from "./useBatchVerification";

const fingerprint = `QE1-SHA3-256:${"a".repeat(64)}`;
const report = (patch: Partial<FileVerification> = {}): FileVerification => ({
  ok: true, verified: true, kem: READY_HEALTH.kem, formatVersion: 4, bytesVerified: 3, publicKeyFingerprint: fingerprint, ...patch
});
const file = (name = "report.pqc", size = 10) => new File([new Uint8Array(size)], name);
const privateKey = new File(["private PEM bytes"], "private.pem");
const limits = { kem: READY_HEALTH.kem, maxFileBytes: 100, maxEncryptedFileBytes: 120 };
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}

describe("useBatchVerification", () => {
  it("verifies sequentially with captured credentials and retains only public result fields", async () => {
    const first = deferred<FileVerification>();
    const verify = vi.fn<VerifyFileOperation>().mockReturnValueOnce(first.promise).mockResolvedValueOnce(report({ bytesVerified: 0 }));
    const { result } = renderHook(() => useBatchVerification(verify));
    const files = [file("first.pqc"), file("empty.pqc")];
    act(() => result.current.start(files, privateKey, "private password", limits));
    expect(verify).toHaveBeenCalledTimes(1);
    expect(verify).toHaveBeenCalledWith(files[0], privateKey, "private password", expect.any(AbortSignal));
    expect(result.current.items.map((item) => item.status)).toEqual(["processing", "queued"]);
    await act(async () => first.resolve({ ...report(), privateData: "must not be retained" } as FileVerification));
    expect(verify).toHaveBeenCalledTimes(2);
    expect(result.current.items.map((item) => item.status)).toEqual(["complete", "complete"]);
    expect(result.current.items[0].result).toEqual(report());
    expect(result.current.items[1].result?.bytesVerified).toBe(0);
    expect(result.current.busy).toBe(false);
  });

  it("supports legacy v3 files with the inspected legacy key algorithm", async () => {
    const verify = vi.fn<VerifyFileOperation>().mockResolvedValue(report({ kem: "ML-KEM-768", formatVersion: 3 }));
    const { result } = renderHook(() => useBatchVerification(verify));
    await act(async () => result.current.start([file()], privateKey, "password", { ...limits, kem: "ML-KEM-768" }));
    expect(result.current.items[0].status).toBe("complete");
  });

  it.each([
    { ok: false }, { ok: "true" }, { verified: false }, { verified: 1 },
    { formatVersion: 2 }, { formatVersion: 5 }, { formatVersion: 3.5 },
    { kem: "other key algorithm" }, { bytesVerified: -1 }, { bytesVerified: 101 }, { bytesVerified: 11 },
    { bytesVerified: 0.5 }, { bytesVerified: Number.NaN },
    { publicKeyFingerprint: "short" }, { publicKeyFingerprint: `${fingerprint}\n` },
    { publicKeyFingerprint: fingerprint.toUpperCase() }
  ])("rejects an incomplete or inconsistent authentication report (%j)", async (patch) => {
    const verify = vi.fn<VerifyFileOperation>().mockResolvedValue(report(patch as Partial<FileVerification>));
    const { result } = renderHook(() => useBatchVerification(verify));
    await act(async () => result.current.start([file()], privateKey, "password", limits));
    expect(result.current.items[0].status).toBe("failed");
    expect(result.current.items[0].result).toBeUndefined();
    expect(result.current.items[0].error).toMatch(/could not verify/);
    expect(verify).toHaveBeenCalledOnce();
  });

  it("rejects inconsistent recipient fingerprints across files verified with one key", async () => {
    const verify = vi.fn<VerifyFileOperation>().mockResolvedValueOnce(report())
      .mockResolvedValueOnce(report({ publicKeyFingerprint: `QE1-SHA3-256:${"b".repeat(64)}` }));
    const { result } = renderHook(() => useBatchVerification(verify));
    await act(async () => result.current.start([file("a.pqc"), file("b.pqc")], privateKey, "password", limits));
    expect(result.current.items.map((item) => item.status)).toEqual(["complete", "failed"]);
  });

  it("continues after authentication, busy, and unexpected failures without retrying", async () => {
    const verify = vi.fn<VerifyFileOperation>()
      .mockRejectedValueOnce(new ApiError(400, "verification_failed", "raw authentication detail"))
      .mockRejectedValueOnce(new ApiError(429, "server_busy", "Wait for the current operation to finish."))
      .mockRejectedValueOnce(new Error("secret diagnostic"))
      .mockResolvedValueOnce(report());
    const { result } = renderHook(() => useBatchVerification(verify));
    const files = [file("a.pqc"), file("b.pqc"), file("c.pqc"), file("d.pqc")];
    await act(async () => result.current.start(files, privateKey, "password", limits));
    expect(verify.mock.calls.map(([input]) => input)).toEqual(files);
    expect(result.current.items.map((item) => item.status)).toEqual(["failed", "failed", "failed", "complete"]);
    expect(result.current.items[0].error).toContain("could not be authenticated");
    expect(result.current.items[1].error).toContain("Wait for the current operation");
    expect(JSON.stringify(result.current.items)).not.toContain("secret diagnostic");
    expect(JSON.stringify(result.current.items)).not.toContain("raw authentication detail");
  });

  it("cancels queued work, suppresses late success, and holds admission until the request settles", async () => {
    const pending = deferred<FileVerification>();
    const verify = vi.fn<VerifyFileOperation>().mockReturnValue(pending.promise);
    const { result } = renderHook(() => useBatchVerification(verify));
    act(() => result.current.start([file("a.pqc"), file("b.pqc")], privateKey, "password", limits));
    act(() => { result.current.cancel(); result.current.clear(); result.current.start([file()], privateKey, "new password", limits); });
    expect(result.current.items.map((item) => item.status)).toEqual(["cancelled", "cancelled"]);
    expect(result.current.busy).toBe(true);
    expect(verify.mock.calls[0][3]?.aborted).toBe(true);
    expect(verify).toHaveBeenCalledOnce();
    await act(async () => pending.resolve(report()));
    expect(result.current.busy).toBe(false);
    expect(result.current.items.every((item) => !item.result)).toBe(true);
    act(() => result.current.clear());
    expect(result.current.items).toEqual([]);
  });

  it("aborts on unmount and never advances to the next file", async () => {
    const pending = deferred<FileVerification>();
    const verify = vi.fn<VerifyFileOperation>().mockReturnValue(pending.promise);
    const { result, unmount } = renderHook(() => useBatchVerification(verify));
    act(() => result.current.start([file(), file()], privateKey, "password", limits));
    unmount();
    expect(verify.mock.calls[0][3]?.aborted).toBe(true);
    await act(async () => pending.resolve(report()));
    expect(verify).toHaveBeenCalledOnce();
  });

  it("rejects invalid limits and oversized selections before queueing", () => {
    const verify = vi.fn<VerifyFileOperation>();
    const { result } = renderHook(() => useBatchVerification(verify));
    act(() => {
      result.current.start([], privateKey, "password", limits);
      result.current.start(Array.from({ length: 26 }, () => file("x", 1)), privateKey, "password", limits);
      result.current.start([file("a", 70), file("b", 70)], privateKey, "password", limits);
      result.current.start([file()], privateKey, "password", { ...limits, maxFileBytes: Number.NaN });
      result.current.start([file()], privateKey, "", limits);
    });
    expect(verify).not.toHaveBeenCalled();
    expect(result.current.items).toEqual([]);
  });

  it("exports an explicit unsigned summary of mixed results without secret or extra fields", async () => {
    const pending = deferred<FileVerification>();
    const verify = vi.fn<VerifyFileOperation>().mockResolvedValueOnce(report())
      .mockRejectedValueOnce(new ApiError(400, "private_key_failed", "Wrong password"))
      .mockReturnValueOnce(pending.promise);
    const { result } = renderHook(() => useBatchVerification(verify));
    await act(async () => result.current.start([file("same.pqc"), file("same.pqc"), file("third.pqc")], privateKey, "private password", limits));
    expect(() => batchVerificationReport(result.current.items)).toThrow("has not finished");
    act(() => result.current.cancel());
    await act(async () => pending.resolve(report()));
    const output = batchVerificationReport(result.current.items);
    expect(output.totals).toEqual({ files: 3, authenticated: 1, failed: 1, cancelled: 1 });
    expect(output.files.map((item) => item.status)).toEqual(["authenticated", "failed", "cancelled"]);
    expect(output.files.map((item) => item.index)).toEqual([1, 2, 3]);
    expect(output.files[0].verification?.publicKeyFingerprint).toBe(fingerprint);
    expect(output.notice).toContain("Unsigned");
    expect(output.notice).toContain("does not identify the sender");
    const json = JSON.stringify(output);
    expect(json).not.toContain("private password");
    expect(json).not.toContain("private PEM bytes");
    expect(json).not.toContain("blob");
  });
});
