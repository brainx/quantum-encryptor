import { useCallback } from "react";
import { ApiError, type FileVerification, type VerifyFileOperation } from "../../api";
import { safeOperationError } from "../../api/errors";
import { useBatchFiles, validateBatchFiles, type BatchFileItem } from "../../hooks/useBatchFiles";
import { isPublicKeyFingerprint } from "../../lib/recipientFingerprint";

export type BatchVerificationItem = BatchFileItem<FileVerification>;
type VerificationLimits = { kem: string; maxFileBytes: number; maxEncryptedFileBytes: number };

function verificationError(error: unknown): string {
  if (error instanceof ApiError && ["verification_failed", "private_key_failed", "decryption_failed"].includes(error.code)) {
    return "The file could not be authenticated. Check the encrypted file, private key, and password.";
  }
  return safeOperationError(error, "The local service could not verify this file. Check the file and try again.");
}

export function useBatchVerification(verify: VerifyFileOperation) {
  const { items, busy, start: startFiles, cancel, clear } = useBatchFiles<FileVerification>(verificationError);
  const start = useCallback((files: readonly File[], privateKey: File, password: string, limits: VerificationLimits) => {
    if (validateBatchFiles(files, limits.maxEncryptedFileBytes, "verify") || !password || !limits.kem ||
        !Number.isSafeInteger(limits.maxFileBytes) || limits.maxFileBytes < 0) return;
    let fingerprint: string | null = null;
    startFiles(files.map((file) => ({ file, outputFilename: file.name })), async (file, _filename, signal) => {
      const report = await verify(file, privateKey, password, signal);
      if (report?.ok !== true || report.verified !== true || report.kem !== limits.kem ||
          ![3, 4].includes(report.formatVersion) || !Number.isSafeInteger(report.bytesVerified) ||
          report.bytesVerified < 0 || report.bytesVerified > Math.min(limits.maxFileBytes, file.size) ||
          !isPublicKeyFingerprint(report.publicKeyFingerprint) ||
          (fingerprint !== null && fingerprint !== report.publicKeyFingerprint)) {
        throw new ApiError(502, "invalid_verification", "Invalid verification report");
      }
      fingerprint = report.publicKeyFingerprint;
      // Keep only the documented public report fields, never extra response data.
      return { ok: true, verified: true, kem: report.kem, formatVersion: report.formatVersion,
        bytesVerified: report.bytesVerified, publicKeyFingerprint: report.publicKeyFingerprint };
    });
  }, [startFiles, verify]);
  return { items, busy, start, cancel, clear };
}

export function batchVerificationReport(items: readonly BatchVerificationItem[]) {
  if (items.length === 0 || items.some((item) => item.status === "queued" || item.status === "processing")) {
    throw new Error("The batch has not finished.");
  }
  return {
    schemaVersion: 1,
    reportType: "batch-file-verification",
    notice: "Unsigned local report. Authentication does not identify the sender. This report is not proof against later file changes.",
    totals: {
      files: items.length,
      authenticated: items.filter((item) => item.status === "complete").length,
      failed: items.filter((item) => item.status === "failed").length,
      cancelled: items.filter((item) => item.status === "cancelled").length
    },
    files: items.map((item, index) => ({
      index: index + 1,
      filename: item.file.name,
      encryptedBytes: item.file.size,
      status: item.status === "complete" ? "authenticated" : item.status,
      ...(item.result ? { verification: {
        kem: item.result.kem, formatVersion: item.result.formatVersion, bytesVerified: item.result.bytesVerified,
        publicKeyFingerprint: item.result.publicKeyFingerprint
      } } : {}),
      ...(item.error ? { error: item.error } : {})
    }))
  };
}
