import { useEffect } from "react";
import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type DownloadResult, type EncryptFileOperation } from "../../api";
import { MAX_BATCH_FILES, useBatchEncryption, validateBatchFiles } from "./useBatchEncryption";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

const recipient = new File(["public key"], "recipient.pem");
const file = (name: string, size = 1) => new File([new Uint8Array(size)], name);
const download = (filename: string): DownloadResult => ({ filename, blob: new Blob(["encrypted"]) });

describe("validateBatchFiles", () => {
  it("requires files and caps the selection at 25", () => {
    expect(MAX_BATCH_FILES).toBe(25);
    expect(validateBatchFiles([], 100)).toMatch(/choose/i);
    expect(validateBatchFiles(Array.from({ length: 26 }, () => file("same")), 100)).toMatch(/25/);
    expect(validateBatchFiles(Array.from({ length: 25 }, () => file("same")), 100)).toBeNull();
  });

  it("enforces both individual and combined byte limits while allowing empty files", () => {
    expect(validateBatchFiles([file("large", 11)], 10)).toMatch(/exceeds/i);
    expect(validateBatchFiles([file("first", 6), file("second", 5)], 10)).toMatch(/combined/i);
    expect(validateBatchFiles([file("first", 6), file("second", 4)], 10)).toBeNull();
    expect(validateBatchFiles([file("empty", 0)], 0)).toBeNull();
  });
});

describe("useBatchEncryption", () => {
  it("awaits each request before starting the next and retains each download", async () => {
    const files = [file("report.pdf"), file("photo.jpg")];
    const first = deferred<DownloadResult>();
    const second = deferred<DownloadResult>();
    const encrypt = vi.fn<EncryptFileOperation>()
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const { result } = renderHook(() => useBatchEncryption(encrypt));

    act(() => result.current.start(files, recipient));

    expect(result.current.busy).toBe(true);
    expect(result.current.items.map((item) => item.status)).toEqual(["encrypting", "queued"]);
    expect(encrypt).toHaveBeenCalledTimes(1);
    expect(encrypt).toHaveBeenLastCalledWith(files[0], recipient, "report.pdf.pqc", expect.any(AbortSignal));
    const firstDownload = download("report.pdf.pqc");
    await act(async () => first.resolve(firstDownload));

    expect(encrypt).toHaveBeenCalledTimes(2);
    expect(encrypt).toHaveBeenLastCalledWith(files[1], recipient, "photo.jpg.pqc", expect.any(AbortSignal));
    expect(result.current.items[0].result).toBe(firstDownload);
    expect(result.current.items.map((item) => item.status)).toEqual(["complete", "encrypting"]);
    await act(async () => second.resolve(download("photo.jpg.pqc")));

    expect(result.current.items.map((item) => item.status)).toEqual(["complete", "complete"]);
    expect(result.current.busy).toBe(false);
  });

  it("makes case-insensitive filenames unique even when generated suffixes collide with input names", async () => {
    const encrypt = vi.fn<EncryptFileOperation>().mockImplementation(async (_file, _key, name) => download(name));
    const { result } = renderHook(() => useBatchEncryption(encrypt));
    const files = [file("a"), file("a"), file("a-2"), file("A"), file("report.tar.gz")];

    await act(async () => result.current.start(files, recipient));

    const names = result.current.items.map((item) => item.outputFilename);
    expect(names).toEqual(["a.pqc", "a-2.pqc", "a-2-2.pqc", "A-3.pqc", "report.tar.gz.pqc"]);
    expect(new Set(names.map((name) => name.toLowerCase())).size).toBe(files.length);
    expect(new Set(result.current.items.map((item) => item.id)).size).toBe(files.length);
  });

  it("deduplicates filenames after API sanitization of punctuation, controls, and surrounding whitespace", async () => {
    const encrypt = vi.fn<EncryptFileOperation>().mockImplementation(async (_file, _key, name) => download(name));
    const { result } = renderHook(() => useBatchEncryption(encrypt));
    const files = [
      file("a?.txt"),
      file("a*.txt"),
      file("a_.txt"),
      file(" \treport\u0000.txt"),
      file("report.txt"),
      file("\u007freport.txt"),
      file("\u0085report.txt"),
      file("  notes .txt  ")
    ];

    await act(async () => result.current.start(files, recipient));

    const names = result.current.items.map((item) => item.outputFilename);
    expect(names).toEqual([
      "a_.txt.pqc",
      "a_.txt-2.pqc",
      "a_.txt-3.pqc",
      "report.txt.pqc",
      "report.txt-2.pqc",
      "report.txt-3.pqc",
      "report.txt-4.pqc",
      "notes .txt.pqc"
    ]);
    expect(encrypt.mock.calls.map(([, , name]) => name)).toEqual(names);
  });

  it("continues after individual failures and never retries a busy response", async () => {
    const encrypt = vi.fn<EncryptFileOperation>()
      .mockRejectedValueOnce(new ApiError(429, "server_busy", "Wait for the current operation to finish."))
      .mockRejectedValueOnce(new Error("private server detail"))
      .mockResolvedValueOnce(download("third.pqc"));
    const { result } = renderHook(() => useBatchEncryption(encrypt));
    const files = [file("first"), file("second"), file("third")];

    await act(async () => result.current.start(files, recipient));

    expect(encrypt.mock.calls.map(([input]) => input)).toEqual(files);
    expect(result.current.items.map((item) => item.status)).toEqual(["failed", "failed", "complete"]);
    expect(result.current.items[0].error).toBe("Wait for the current operation to finish.");
    expect(result.current.items[1].error).toMatch(/could not encrypt/i);
    expect(result.current.items[1].error).not.toContain("private server detail");
    expect(result.current.busy).toBe(false);
  });

  it("handles a synchronous operation error without abandoning the remaining files", async () => {
    const encrypt = vi.fn<EncryptFileOperation>()
      .mockImplementationOnce(() => { throw new TypeError("private socket detail"); })
      .mockResolvedValueOnce(download("second.pqc"));
    const { result } = renderHook(() => useBatchEncryption(encrypt));

    await act(async () => result.current.start([file("first"), file("second")], recipient));

    expect(result.current.items.map((item) => item.status)).toEqual(["failed", "complete"]);
    expect(result.current.items[0].error).toMatch(/could not reach the local service/i);
    expect(result.current.busy).toBe(false);
  });

  it("guards repeated starts synchronously and rejects empty or oversized selections", async () => {
    const pending = deferred<DownloadResult>();
    const encrypt = vi.fn<EncryptFileOperation>().mockReturnValue(pending.promise);
    const { result } = renderHook(() => useBatchEncryption(encrypt));

    act(() => {
      result.current.start([], recipient);
      result.current.start(Array.from({ length: MAX_BATCH_FILES + 1 }, () => file("extra")), recipient);
    });
    expect(result.current.items).toEqual([]);
    expect(result.current.busy).toBe(false);
    expect(encrypt).not.toHaveBeenCalled();
    act(() => {
      result.current.start([file("first")], recipient);
      result.current.start([file("second")], recipient);
    });
    expect(encrypt).toHaveBeenCalledTimes(1);
    expect(result.current.items[0].file.name).toBe("first");
    await act(async () => pending.resolve(download("first.pqc")));
  });

  it.each(["resolve", "reject"] as const)(
    "cancels queued and current work immediately, rejects overlap, and ignores a late %s",
    async (settlement) => {
      const pending = deferred<DownloadResult>();
      const encrypt = vi.fn<EncryptFileOperation>()
        .mockResolvedValueOnce(download("first.pqc"))
        .mockReturnValueOnce(pending.promise);
      const { result } = renderHook(() => useBatchEncryption(encrypt));
      await act(async () => result.current.start([file("first"), file("second"), file("third")], recipient));
      const signal = encrypt.mock.calls[1][3];

      act(() => {
        result.current.cancel();
        result.current.clear();
        result.current.start([file("overlap")], recipient);
      });

      expect(signal?.aborted).toBe(true);
      expect(result.current.items.map((item) => item.status)).toEqual(["complete", "cancelled", "cancelled"]);
      expect(result.current.busy).toBe(true);
      expect(encrypt).toHaveBeenCalledTimes(2);
      await act(async () => {
        if (settlement === "resolve") pending.resolve(download("late.pqc"));
        else pending.reject(new Error("late failure"));
      });

      expect(result.current.items.map((item) => item.status)).toEqual(["complete", "cancelled", "cancelled"]);
      expect(result.current.items[1].result).toBeUndefined();
      expect(result.current.items[1].error).toBeUndefined();
      expect(result.current.busy).toBe(false);
      expect(encrypt).toHaveBeenCalledTimes(2);
      act(() => result.current.clear());
      expect(result.current.items).toEqual([]);
      encrypt.mockResolvedValueOnce(download("next.pqc"));
      await act(async () => result.current.start([file("next")], recipient));
      expect(result.current.items[0].status).toBe("complete");
    }
  );

  it("treats a settled AbortError as cancellation without starting another file", async () => {
    const encrypt = vi.fn<EncryptFileOperation>().mockRejectedValue(new DOMException("Aborted", "AbortError"));
    const { result } = renderHook(() => useBatchEncryption(encrypt));

    await act(async () => result.current.start([file("first"), file("second")], recipient));

    expect(result.current.items.map((item) => item.status)).toEqual(["cancelled", "cancelled"]);
    expect(result.current.items.every((item) => item.error === undefined)).toBe(true);
    expect(result.current.busy).toBe(false);
    expect(encrypt).toHaveBeenCalledTimes(1);
  });

  it("aborts on unmount and prevents late completion from starting another request", async () => {
    const pending = deferred<DownloadResult>();
    const encrypt = vi.fn<EncryptFileOperation>().mockReturnValue(pending.promise);
    const { result, unmount } = renderHook(() => useBatchEncryption(encrypt));
    act(() => result.current.start([file("first"), file("second")], recipient));
    const signal = encrypt.mock.calls[0][3];

    unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () => pending.resolve(download("late.pqc")));

    expect(encrypt).toHaveBeenCalledTimes(1);
  });

  it("keeps the captured operation for an active batch when the component rerenders", async () => {
    const pending = deferred<DownloadResult>();
    const original = vi.fn<EncryptFileOperation>()
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(download("second.pqc"));
    const replacement = vi.fn<EncryptFileOperation>().mockResolvedValue(download("next.pqc"));
    const { result, rerender } = renderHook(({ encrypt }) => useBatchEncryption(encrypt), {
      initialProps: { encrypt: original }
    });
    act(() => result.current.start([file("first"), file("second")], recipient));
    rerender({ encrypt: replacement });
    act(() => result.current.start([file("overlap")], recipient));

    await act(async () => pending.resolve(download("first.pqc")));

    expect(original).toHaveBeenCalledTimes(2);
    expect(replacement).not.toHaveBeenCalled();
    await act(async () => result.current.start([file("next")], recipient));
    expect(replacement).toHaveBeenCalledTimes(1);
  });

  it("does not overlap an effect-started batch during StrictMode replay", async () => {
    const pending = deferred<DownloadResult>();
    const encrypt = vi.fn<EncryptFileOperation>().mockReturnValueOnce(pending.promise);
    const { result } = renderHook(() => {
      const batch = useBatchEncryption(encrypt);
      useEffect(() => batch.start([file("first"), file("second")], recipient), [batch.start]);
      return batch;
    }, { reactStrictMode: true });

    expect(encrypt).toHaveBeenCalledTimes(1);
    expect(encrypt.mock.calls[0][3]?.aborted).toBe(true);
    expect(result.current.items.map((item) => item.status)).toEqual(["cancelled", "cancelled"]);
    expect(result.current.busy).toBe(true);
    await act(async () => pending.resolve(download("late.pqc")));

    expect(encrypt).toHaveBeenCalledTimes(1);
    expect(result.current.busy).toBe(false);
    expect(result.current.items.every((item) => item.result === undefined)).toBe(true);
  });

  it("remains usable after StrictMode effect cleanup and releases idle results on clear", async () => {
    const encrypt = vi.fn<EncryptFileOperation>().mockResolvedValue(download("first.pqc"));
    const { result } = renderHook(() => useBatchEncryption(encrypt), { reactStrictMode: true });

    await act(async () => result.current.start([file("first")], recipient));
    expect(result.current.items[0].status).toBe("complete");
    expect(result.current.busy).toBe(false);
    expect(encrypt).toHaveBeenCalledTimes(1);
    act(() => result.current.clear());
    expect(result.current.items).toEqual([]);
  });
});
