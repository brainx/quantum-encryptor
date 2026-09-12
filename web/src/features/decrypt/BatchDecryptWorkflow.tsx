import { useEffect, useLayoutEffect, useRef, useState, type ChangeEvent, type DragEvent, type FormEvent } from "react";
import {
  decryptFile,
  ApiError,
  type DownloadResult,
  type DecryptFileOperation,
  type Health,
  type InspectKeyOperation
} from "../../api";
import { safeOperationError } from "../../api/errors";
import { PasswordField } from "../../components/PasswordField";
import { suggestedDecryptedName } from "../../lib/filenames";
import { ActionButton } from "../../components/ActionButton";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { downloadBlob } from "../../lib/download";
import { formatBytes } from "../../lib/format";
import { deriveWorkflowPhase } from "../../lib/workflow";
import { MAX_BATCH_FILES, sanitizeBatchFilename, uniqueBatchFilenames, useBatchFiles, validateBatchFiles } from "../../hooks/useBatchFiles";

export type BatchDecryptWorkflowProps = {
  health: Health;
  inspect?: InspectKeyOperation;
  decrypt?: DecryptFileOperation;
  save?: (result: DownloadResult) => void;
  onPendingResultsChange?: (pending: boolean) => void;
};

const ITEM_STATUS_LABELS = {
  queued: "Queued",
  processing: "Decrypting",
  complete: "Decrypted — ready to download",
  failed: "Failed",
  cancelled: "Cancelled"
};

function decryptionError(error: unknown): string {
  if (error instanceof ApiError && ["decryption_failed", "private_key_failed"].includes(error.code)) {
    return "The file could not be authenticated. Check the encrypted file, private key, and password.";
  }
  return safeOperationError(error, "The local service could not complete decryption. Try again.");
}

function outputName(file: File): string {
  const name = sanitizeBatchFilename(file.name);
  if (name.toLowerCase().endsWith("_encrypted.pqc")) {
    return name.slice(0, -"_encrypted.pqc".length) || "decrypted.bin";
  }
  if (name.toLowerCase().endsWith(".pqc")) return name.slice(0, -4) || "decrypted.bin";
  return suggestedDecryptedName(file);
}

export function BatchDecryptWorkflow({
  health,
  inspect,
  decrypt = decryptFile,
  save = downloadBlob,
  onPendingResultsChange
}: BatchDecryptWorkflowProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [privateKey, setPrivateKey] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const [downloaded, setDownloaded] = useState<Set<number>>(() => new Set());
  const [downloadErrors, setDownloadErrors] = useState<Record<number, string>>({});
  const [cancelling, setCancelling] = useState(false);
  const { items, busy, start, cancel, clear } = useBatchFiles(decryptionError);
  const capability = health.capabilities.decrypt;
  const locked = busy || items.length > 0;
  const { result: inspection, error: inspectionError, loading: inspecting } = useKeyInspection(
    capability.available ? privateKey : null,
    health.maxPemBytes,
    inspect
  );
  const keyError = privateKey && privateKey.size > health.maxPemBytes
    ? `This key file exceeds the ${health.maxPemBytes.toLocaleString()} byte limit.`
    : null;
  const supportedKey = Boolean(
    inspection?.ok && inspection.keyInfo.key_type === "private" && inspection.keyInfo.private_key_encrypted === true
  );
  const validationError = validateBatchFiles(files, health.maxEncryptedFileBytes, "decrypt");
  function getReadinessReason(): string | null {
    if (!capability.available) return capability.reason;
    if (validationError) return validationError;
    if (!privateKey) return "Choose a private key.";
    if (keyError) return keyError;
    if (inspecting) return "Inspecting private key.";
    if (inspectionError || !inspection?.ok) return "The private key could not be inspected.";
    if (!supportedKey) return "A supported encrypted private key is required to decrypt files.";
    if (!password) return "Enter the private key password.";
    return null;
  }
  const readinessReason = getReadinessReason();
  const canStart = !locked && !readinessReason;
  const completeCount = items.filter((item) => item.status === "complete").length;
  const failedCount = items.filter((item) => item.status === "failed").length;
  const cancelledCount = items.filter((item) => item.status === "cancelled").length;
  const processedCount = completeCount + failedCount + cancelledCount;
  const pendingResults = items.some((item) => Boolean(item.result));
  const pendingCallbackRef = useRef(onPendingResultsChange);

  useEffect(() => {
    pendingCallbackRef.current = onPendingResultsChange;
  }, [onPendingResultsChange]);

  useLayoutEffect(() => {
    pendingCallbackRef.current?.(pendingResults);
  }, [pendingResults]);

  useEffect(() => () => pendingCallbackRef.current?.(false), []);

  function addFiles(nextFiles: File[]) {
    if (locked || nextFiles.length === 0) return;
    const nextSelection = [...files, ...nextFiles];
    const error = validateBatchFiles(nextSelection, health.maxEncryptedFileBytes, "decrypt");
    if (error) {
      setSelectionError(`Files were not added. ${error}`);
      return;
    }
    setFiles(nextSelection);
    setSelectionError(null);
  }

  function selectFiles(event: ChangeEvent<HTMLInputElement>) {
    const selectedFiles = Array.from(event.currentTarget.files ?? []);
    event.currentTarget.value = "";
    addFiles(selectedFiles);
  }

  function dropFiles(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    addFiles(Array.from(event.dataTransfer.files));
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canStart || !privateKey) return;
    setSelectionError(null);
    setCancelling(false);
    const batchPassword = password;
    const batchKey = privateKey;
    const names = uniqueBatchFilenames(files.map(outputName));
    setPassword("");
    start(
      files.map((file, index) => ({ file, outputFilename: names[index] })),
      (file, filename, signal) => decrypt(file, batchKey, batchPassword, filename, signal)
    );
  }

  function clearBatch() {
    if (busy) return;
    clear();
    setFiles([]);
    setPrivateKey(null);
    setPassword("");
    setDownloaded(new Set());
    setDownloadErrors({});
    setSelectionError(null);
    setCancelling(false);
  }

  function download(id: number, result: DownloadResult) {
    try {
      save(result);
      setDownloaded((current) => new Set(current).add(id));
      setDownloadErrors((current) => {
        const next = { ...current };
        delete next[id];
        return next;
      });
    } catch {
      setDownloadErrors((current) => ({
        ...current,
        [id]: "The download could not start. Try downloading this file again."
      }));
    }
  }

  return (
    <WorkflowLayout
      busy={busy || inspecting}
      capability={capability}
      description="Open several encrypted files with one private key, then download each authenticated result."
      phase={deriveWorkflowPhase({ ready: canStart || items.length > 0, complete: items.length > 0 && completeCount === items.length })}
      title="Decrypt multiple files"
    >
      {capability.available && (
        <form className="decryption-form" onSubmit={submit}>
          <div className="file-picker-field">
            <label
              className={files.length ? "file-picker file-picker-selected" : "file-picker"}
              htmlFor="batch-decrypt-files"
              onDragOver={(event) => event.preventDefault()}
              onDrop={dropFiles}
            >
              <span className="file-picker-label">Files to decrypt</span>
              <span className="file-picker-prompt">Choose files or drop them here</span>
              <span className="file-picker-selection">
                {files.length ? `${files.length} files · ${formatBytes(files.reduce((total, file) => total + file.size, 0))}` : "No files selected"}
              </span>
              <input
                accept=".pqc,application/octet-stream"
                aria-label="Files to decrypt"
                aria-describedby={`batch-file-limits${selectionError ? " batch-file-error" : ""}`}
                aria-invalid={selectionError ? true : undefined}
                className="file-picker-input"
                disabled={locked}
                id="batch-decrypt-files"
                multiple
                onChange={selectFiles}
                type="file"
              />
            </label>
            <p className="field-hint" id="batch-file-limits">
              Up to {MAX_BATCH_FILES} files and {formatBytes(health.maxEncryptedFileBytes)} total. Files are processed one at a time.
            </p>
            {selectionError && <p className="field-error" id="batch-file-error" role="alert">{selectionError}</p>}
          </div>

          {!items.length && files.length > 0 && (
            <ul aria-label="Selected files" className="batch-file-list">
              {files.map((file, index) => (
                <li key={index}>
                  <span className="batch-file-name">{file.name}<small>{formatBytes(file.size)}</small></span>
                  <button
                    aria-label={`Remove ${file.name}`}
                    disabled={locked}
                    onClick={() => {
                      if (locked) return;
                      setFiles((current) => current.filter((_, position) => position !== index));
                      setSelectionError(null);
                    }}
                    type="button"
                  >Remove</button>
                </li>
              ))}
            </ul>
          )}

          <FilePicker
            accept=".pem,application/x-pem-file"
            disabled={locked}
            error={keyError ?? undefined}
            file={privateKey}
            hint={`Encrypted private PEM key, up to ${formatBytes(health.maxPemBytes)}`}
            id="batch-decrypt-private-key"
            label="Private key"
            onFile={(file) => { if (!locked) { setPrivateKey(file); setPassword(""); } }}
          />

          {supportedKey && (
            <section aria-label="Private key review" className="workflow-review">
              <h2>Supported encrypted private key; match not yet verified</h2>
              <dl className="review-list">
                <div><dt>Hybrid suite</dt><dd>{inspection?.keyInfo.kem}</dd></div>
                <div><dt>Key format</dt><dd>{inspection?.keyInfo.private_key_format_version ?? "Not declared"}</dd></div>
              </dl>
              <p className="field-hint">Each file must authenticate with this private key before its plaintext is available.</p>
            </section>
          )}
          <PasswordField
            autoComplete="current-password"
            disabled={locked}
            id="batch-decrypt-password"
            label="Private key password"
            onChange={(value) => { if (!locked) setPassword(value); }}
            value={password}
          />
          {!locked && readinessReason && <p className="workflow-readiness-reason" role="status">{readinessReason}</p>}
          {!items.length && <ActionButton busyLabel="Decrypting batch" disabled={!canStart} type="submit">Decrypt batch</ActionButton>}
          {busy && (
            <button
              disabled={cancelling}
              onClick={() => { setCancelling(true); cancel(); }}
              type="button"
            >{cancelling ? "Cancelling batch" : "Cancel batch"}</button>
          )}
        </form>
      )}

      {items.length > 0 && (
        <section aria-label="Batch results" className="batch-results">
          <h2>{busy ? "Decrypting batch" : "Batch results"}</h2>
          <p aria-live="polite" role="status">
            {processedCount} of {items.length} files processed · {completeCount} decrypted · {failedCount} failed · {cancelledCount} cancelled
          </p>
          {cancelling && busy && <Notice kind="info">Cancellation requested. Completed files remain available to download.</Notice>}
          {completeCount > 0 && (
            <Notice kind="info">
              Download each decrypted file below. Plaintext remains in this tab even after a download starts. Clear the batch when finished.
            </Notice>
          )}
          <ul aria-label="File decryption results" className="batch-file-list">
            {items.map((item) => (
              <li key={item.id}>
                <div className="batch-file-name">
                  <strong>{item.file.name}</strong>
                  <small>{item.result?.filename ?? item.outputFilename}</small>
                  <span>
                    {item.status === "complete" && downloaded.has(item.id) ? "Download started" : ITEM_STATUS_LABELS[item.status]}
                  </span>
                  {item.error && <p className="field-error" role="alert">{item.error}</p>}
                  {downloadErrors[item.id] && <p className="field-error" role="alert">{downloadErrors[item.id]}</p>}
                </div>
                {item.result && (
                  <button aria-label={`Download ${item.result.filename}`} onClick={() => download(item.id, item.result!)} type="button">
                    Download
                  </button>
                )}
              </li>
            ))}
          </ul>
          <button disabled={busy} onClick={clearBatch} type="button">Clear batch</button>
        </section>
      )}
    </WorkflowLayout>
  );
}
