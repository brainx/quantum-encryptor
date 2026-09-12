import { useEffect, useLayoutEffect, useRef, useState, type ChangeEvent, type DragEvent, type FormEvent } from "react";
import {
  encryptFile,
  type DownloadResult,
  type EncryptFileOperation,
  type Health,
  type InspectKeyOperation
} from "../../api";
import { ActionButton } from "../../components/ActionButton";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { downloadBlob } from "../../lib/download";
import { formatBytes } from "../../lib/format";
import { deriveWorkflowPhase } from "../../lib/workflow";
import { MAX_BATCH_FILES, useBatchEncryption, validateBatchFiles } from "./useBatchEncryption";

export type BatchEncryptWorkflowProps = {
  health: Health;
  inspect?: InspectKeyOperation;
  encrypt?: EncryptFileOperation;
  save?: (result: DownloadResult) => void;
  onPendingResultsChange?: (pending: boolean) => void;
};

const FINGERPRINT_PREFIX = "QE1-SHA3-256:";
const ITEM_STATUS_LABELS = {
  queued: "Queued",
  encrypting: "Encrypting",
  complete: "Encrypted — ready to download",
  failed: "Failed",
  cancelled: "Cancelled"
};

function validFingerprint(value: unknown): value is string {
  return typeof value === "string" && value.length === FINGERPRINT_PREFIX.length + 64 &&
    /^QE1-SHA3-256:[0-9a-f]{64}$/.test(value);
}

export function BatchEncryptWorkflow({
  health,
  inspect,
  encrypt = encryptFile,
  save = downloadBlob,
  onPendingResultsChange
}: BatchEncryptWorkflowProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [publicKey, setPublicKey] = useState<File | null>(null);
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const [downloaded, setDownloaded] = useState<Set<number>>(() => new Set());
  const [downloadErrors, setDownloadErrors] = useState<Record<number, string>>({});
  const [cancelling, setCancelling] = useState(false);
  const { items, busy, start, cancel, clear } = useBatchEncryption(encrypt);
  const capability = health.capabilities.encrypt;
  const locked = busy || items.length > 0;
  const { result: inspection, error: inspectionError, loading: inspecting } = useKeyInspection(
    capability.available ? publicKey : null,
    health.maxPemBytes,
    inspect
  );
  const keyError = publicKey && publicKey.size > health.maxPemBytes
    ? `This key file exceeds the ${health.maxPemBytes.toLocaleString()} byte limit.`
    : null;
  const compatibleKey = Boolean(
    inspection?.ok && inspection.keyInfo.key_type === "public" &&
    inspection.keyInfo.kem === health.kem && validFingerprint(inspection.keyInfo.public_key_fingerprint)
  );
  const fingerprint = compatibleKey ? inspection?.keyInfo.public_key_fingerprint : null;
  const validationError = validateBatchFiles(files, health.maxFileBytes);
  function getReadinessReason(): string | null {
    if (!capability.available) return capability.reason;
    if (validationError) return validationError;
    if (!publicKey) return "Choose the recipient's public key.";
    if (keyError) return keyError;
    if (inspecting) return "Inspecting recipient key.";
    if (inspectionError || !inspection?.ok) return "The recipient key could not be inspected.";
    if (inspection.keyInfo.key_type !== "public") return "A public key is required to encrypt files.";
    if (inspection.keyInfo.kem !== health.kem) {
      return `This public key uses ${inspection.keyInfo.kem}; encryption requires ${health.kem}.`;
    }
    if (!validFingerprint(inspection.keyInfo.public_key_fingerprint)) {
      return "The recipient public key did not provide a valid fingerprint.";
    }
    return null;
  }
  const readinessReason = getReadinessReason();
  const canStart = !locked && !readinessReason;
  const completeCount = items.filter((item) => item.status === "complete").length;
  const failedCount = items.filter((item) => item.status === "failed").length;
  const cancelledCount = items.filter((item) => item.status === "cancelled").length;
  const processedCount = completeCount + failedCount + cancelledCount;
  const pendingResults = items.some((item) => item.result && !downloaded.has(item.id));
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
    const error = validateBatchFiles(nextSelection, health.maxFileBytes);
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
    if (!canStart || !publicKey) return;
    setSelectionError(null);
    setCancelling(false);
    start(files, publicKey);
  }

  function clearBatch() {
    if (busy) return;
    clear();
    setFiles([]);
    setPublicKey(null);
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
      description="Encrypt several files for one recipient, then download each protected file."
      phase={deriveWorkflowPhase({ ready: canStart || items.length > 0, complete: items.length > 0 && completeCount === items.length })}
      title="Encrypt multiple files"
    >
      {capability.available && (
        <form className="batch-encryption-form" onSubmit={submit}>
          <div className="file-picker-field">
            <label
              className={files.length ? "file-picker file-picker-selected" : "file-picker"}
              htmlFor="batch-encrypt-files"
              onDragOver={(event) => event.preventDefault()}
              onDrop={dropFiles}
            >
              <span className="file-picker-label">Files to encrypt</span>
              <span className="file-picker-prompt">Choose files or drop them here</span>
              <span className="file-picker-selection">
                {files.length ? `${files.length} files · ${formatBytes(files.reduce((total, file) => total + file.size, 0))}` : "No files selected"}
              </span>
              <input
                aria-label="Files to encrypt"
                aria-describedby={`batch-file-limits${selectionError ? " batch-file-error" : ""}`}
                aria-invalid={selectionError ? true : undefined}
                className="file-picker-input"
                disabled={locked}
                id="batch-encrypt-files"
                multiple
                onChange={selectFiles}
                type="file"
              />
            </label>
            <p className="field-hint" id="batch-file-limits">
              Up to {MAX_BATCH_FILES} files and {formatBytes(health.maxFileBytes)} total. Files are processed one at a time.
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
            file={publicKey}
            hint={`Recipient public PEM key, up to ${formatBytes(health.maxPemBytes)}`}
            id="batch-encrypt-public-key"
            label="Recipient public key"
            onFile={(file) => { if (!locked) setPublicKey(file); }}
          />

          {fingerprint && (
            <section aria-label="Recipient review" className="workflow-review">
              <h2>Compatible public key</h2>
              <dl className="review-list">
                <div><dt>Recipient public-key fingerprint</dt><dd>{fingerprint}</dd></div>
              </dl>
              <p className="field-hint">
                Compare this complete fingerprint with the recipient over a separate trusted channel before encrypting.
              </p>
            </section>
          )}
          {!locked && readinessReason && <p className="workflow-readiness-reason" role="status">{readinessReason}</p>}
          {!items.length && <ActionButton busyLabel="Encrypting batch" disabled={!canStart} type="submit">Encrypt batch</ActionButton>}
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
          <h2>{busy ? "Encrypting batch" : "Batch results"}</h2>
          <p aria-live="polite" role="status">
            {processedCount} of {items.length} files processed · {completeCount} encrypted · {failedCount} failed · {cancelledCount} cancelled
          </p>
          {cancelling && busy && <Notice kind="info">Cancellation requested. Completed files remain available to download.</Notice>}
          {completeCount > 0 && (
            <Notice kind="info">
              Download each encrypted file below. Results stay in this tab until you clear the batch or leave the page.
            </Notice>
          )}
          <ul aria-label="File encryption results" className="batch-file-list">
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
