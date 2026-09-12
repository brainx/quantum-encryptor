import { useCallback } from "react";
import type { EncryptFileOperation } from "../../api";
import { safeOperationError } from "../../api/errors";
import { MAX_BATCH_FILES, sanitizeBatchFilename, uniqueBatchFilenames, useBatchFiles, type BatchFileItem } from "../../hooks/useBatchFiles";

export { MAX_BATCH_FILES, validateBatchFiles } from "../../hooks/useBatchFiles";

export type BatchEncryptionItem = Omit<BatchFileItem, "status"> & {
  status: Exclude<BatchFileItem["status"], "processing"> | "encrypting";
};

function encryptionError(error: unknown): string {
  return safeOperationError(error, "Could not encrypt this file. Confirm the recipient key and try again.");
}

export function useBatchEncryption(encrypt: EncryptFileOperation) {
  const { items, busy, start: startFiles, cancel, clear } = useBatchFiles(encryptionError);
  const start = useCallback((files: readonly File[], publicKey: File) => {
    if (files.length === 0 || files.length > MAX_BATCH_FILES) return;
    const names = uniqueBatchFilenames(files.map((file) => `${sanitizeBatchFilename(file.name)}.pqc`));
    startFiles(
      files.map((file, index) => ({ file, outputFilename: names[index] })),
      (file, outputFilename, signal) => encrypt(file, publicKey, outputFilename, signal)
    );
  }, [encrypt, startFiles]);
  const encryptionItems: BatchEncryptionItem[] = items.map((item) => ({
    ...item,
    status: item.status === "processing" ? "encrypting" : item.status
  }));
  return { items: encryptionItems, busy, start, cancel, clear };
}
