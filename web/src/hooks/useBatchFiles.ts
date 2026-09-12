import { useCallback, useEffect, useRef, useState } from "react";
import type { DownloadResult } from "../api";
import { isAbortError } from "../api/errors";

export const MAX_BATCH_FILES = 25;
export type BatchFileInput = { file: File; outputFilename: string };
export type BatchFileItem = BatchFileInput & {
  id: number;
  status: "queued" | "processing" | "complete" | "failed" | "cancelled";
  result?: DownloadResult;
  error?: string;
};
type BatchOperation = (file: File, outputFilename: string, signal: AbortSignal) => Promise<DownloadResult>;
type BatchRun = { controller: AbortController; cancelled: boolean; operation: BatchOperation | null };

export function validateBatchFiles(files: readonly File[], maxBytes: number, action = "encrypt"): string | null {
  if (files.length === 0) return `Choose files to ${action}.`;
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

export function sanitizeBatchFilename(filename: string): string {
  // Match the API before allocating unique names; Python strip includes U+0085.
  return (filename.split("/").pop() ?? "")
    .replace(/[\x00-\x1f\x7f]+/g, "")
    .replace(/[\\/:;"<>|?*]+/g, "_")
    .replace(/^[\s\u0085]+|[\s\u0085]+$/g, "") || "file";
}

export function uniqueBatchFilenames(filenames: readonly string[]): string[] {
  const usedNames = new Set<string>();
  return filenames.map((filename) => {
    const normalized = sanitizeBatchFilename(filename);
    const dot = normalized.lastIndexOf(".");
    const stem = dot > 0 ? normalized.slice(0, dot) : normalized;
    const extension = dot > 0 ? normalized.slice(dot) : "";
    let candidate = normalized;
    let suffix = 2;
    while (usedNames.has(candidate.toLowerCase())) candidate = `${stem}-${suffix++}${extension}`;
    usedNames.add(candidate.toLowerCase());
    return candidate;
  });
}

function cancelUnfinished(items: BatchFileItem[]): BatchFileItem[] {
  return items.map((item) =>
    item.status === "queued" || item.status === "processing" ? { ...item, status: "cancelled" } : item
  );
}

export function useBatchFiles(formatError: (error: unknown) => string) {
  const [items, setItems] = useState<BatchFileItem[]>([]);
  const [busy, setBusy] = useState(false);
  const mountedRef = useRef(true);
  const activeRef = useRef<BatchRun | null>(null);
  const nextIdRef = useRef(0);

  const cancel = useCallback(() => {
    const run = activeRef.current;
    if (!run) return;
    run.cancelled = true;
    run.operation = null;
    if (mountedRef.current) setItems(cancelUnfinished);
    run.controller.abort();
    // Keep admission until the active promise settles, even if it ignores abort.
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      cancel();
      mountedRef.current = false;
    };
  }, [cancel]);

  const start = useCallback((inputs: readonly BatchFileInput[], operation: BatchOperation) => {
    if (!mountedRef.current || activeRef.current || inputs.length === 0 || inputs.length > MAX_BATCH_FILES) return;
    const batch: BatchFileItem[] = inputs.map((input) => ({ ...input, id: nextIdRef.current++, status: "queued" }));
    const run: BatchRun = { controller: new AbortController(), cancelled: false, operation };
    activeRef.current = run;
    setItems(batch);
    setBusy(true);

    const isCurrent = () => mountedRef.current && activeRef.current === run && !run.cancelled;
    const updateItem = (id: number, update: Partial<BatchFileItem>) => {
      setItems((current) => current.map((item) => item.id === id ? { ...item, ...update } : item));
    };

    async function processBatch() {
      try {
        for (const item of batch) {
          if (!isCurrent() || !run.operation) break;
          updateItem(item.id, { status: "processing" });
          try {
            const result = await run.operation(item.file, item.outputFilename, run.controller.signal);
            if (!isCurrent()) break;
            updateItem(item.id, { status: "complete", result });
          } catch (error: unknown) {
            if (!isCurrent()) break;
            if (isAbortError(error)) {
              cancel();
              break;
            }
            updateItem(item.id, { status: "failed", error: formatError(error) });
          }
        }
      } finally {
        // Finished items retain only files, results, and safe errors, never the
        // operation closure that can capture a private-key password.
        run.operation = null;
        if (activeRef.current === run) {
          activeRef.current = null;
          if (mountedRef.current) setBusy(false);
        }
      }
    }

    void processBatch();
  }, [cancel, formatError]);

  const clear = useCallback(() => {
    if (mountedRef.current && !activeRef.current) setItems([]);
  }, []);

  return { items, busy, start, cancel, clear };
}
