import { useCallback, useEffect, useRef, useState } from "react";
import type { DownloadResult, EncryptFileOperation } from "../../api";
import { isAbortError, safeOperationError } from "../../api/errors";

export const MAX_BATCH_FILES = 25;

export type BatchEncryptionItem = {
  id: number;
  file: File;
  outputFilename: string;
  status: "queued" | "encrypting" | "complete" | "failed" | "cancelled";
  result?: DownloadResult;
  error?: string;
};

export function validateBatchFiles(files: readonly File[], maxBytes: number): string | null {
  if (files.length === 0) return "Choose files to encrypt.";
  if (files.length > MAX_BATCH_FILES) return `Choose up to ${MAX_BATCH_FILES} files per batch.`;
  if (!Number.isFinite(maxBytes) || maxBytes < 0) return "The file size limit is unavailable.";
  if (files.some((file) => file.size > maxBytes)) {
    return `A selected file exceeds the ${maxBytes.toLocaleString()} byte limit.`;
  }
  if (files.reduce((total, file) => total + file.size, 0) > maxBytes) {
    return `The combined file size exceeds the ${maxBytes.toLocaleString()} byte batch limit.`;
  }
  return null;
}

function cancelUnfinished(items: BatchEncryptionItem[]): BatchEncryptionItem[] {
  return items.map((item) =>
    item.status === "queued" || item.status === "encrypting" ? { ...item, status: "cancelled" } : item
  );
}

function outputBasename(filename: string): string {
  // Normalize before deduplication so the API's download-name sanitizer cannot
  // collapse distinct batch outputs. Python strip also removes U+0085.
  return (filename.split("/").pop() ?? "")
    .replace(/[\x00-\x1f\x7f]+/g, "")
    .replace(/[\\/:;"<>|?*]+/g, "_")
    .replace(/^[\s\u0085]+|[\s\u0085]+$/g, "") || "file";
}

type BatchRun = {
  controller: AbortController;
  cancelled: boolean;
};

export function useBatchEncryption(encrypt: EncryptFileOperation) {
  const [items, setItems] = useState<BatchEncryptionItem[]>([]);
  const [busy, setBusy] = useState(false);
  const mountedRef = useRef(true);
  const activeRef = useRef<BatchRun | null>(null);
  const nextIdRef = useRef(0);

  const cancel = useCallback(() => {
    const run = activeRef.current;
    if (!run) return;
    run.cancelled = true;
    if (mountedRef.current) setItems(cancelUnfinished);
    run.controller.abort();
    // Aborting fetch does not guarantee an injected operation has settled.
    // Its finally block owns clearing admission and the busy state.
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      cancel();
      mountedRef.current = false;
    };
  }, [cancel]);

  const start = useCallback((files: readonly File[], publicKey: File) => {
    if (!mountedRef.current || activeRef.current || files.length === 0 || files.length > MAX_BATCH_FILES) return;

    const usedNames = new Set<string>();
    const batch: BatchEncryptionItem[] = files.map((file) => {
      const basename = outputBasename(file.name);
      let outputFilename = `${basename}.pqc`;
      let suffix = 2;
      while (usedNames.has(outputFilename.toLowerCase())) {
        outputFilename = `${basename}-${suffix++}.pqc`;
      }
      usedNames.add(outputFilename.toLowerCase());
      return { id: nextIdRef.current++, file, outputFilename, status: "queued" };
    });
    const run: BatchRun = { controller: new AbortController(), cancelled: false };
    activeRef.current = run;
    setItems(batch);
    setBusy(true);

    const isCurrent = () => mountedRef.current && activeRef.current === run && !run.cancelled;
    const updateItem = (id: number, update: Partial<BatchEncryptionItem>) => {
      setItems((current) => current.map((item) => item.id === id ? { ...item, ...update } : item));
    };

    async function processBatch() {
      try {
        for (const item of batch) {
          if (!isCurrent()) break;
          updateItem(item.id, { status: "encrypting" });
          try {
            const result = await encrypt(item.file, publicKey, item.outputFilename, run.controller.signal);
            if (!isCurrent()) break;
            updateItem(item.id, { status: "complete", result });
          } catch (error: unknown) {
            if (!isCurrent()) break;
            if (isAbortError(error)) {
              cancel();
              break;
            }
            updateItem(item.id, {
              status: "failed",
              error: safeOperationError(error, "Could not encrypt this file. Confirm the recipient key and try again.")
            });
          }
        }
      } finally {
        if (activeRef.current === run) {
          activeRef.current = null;
          if (mountedRef.current) setBusy(false);
        }
      }
    }

    void processBatch();
  }, [cancel, encrypt]);

  const clear = useCallback(() => {
    if (mountedRef.current && !activeRef.current) setItems([]);
  }, []);

  return { items, busy, start, cancel, clear };
}
