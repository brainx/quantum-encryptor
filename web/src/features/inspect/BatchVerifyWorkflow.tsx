import { useEffect, useLayoutEffect, useRef, useState, type ChangeEvent, type DragEvent, type FormEvent } from "react";
import { verifyFile, type DownloadResult, type Health, type InspectKeyOperation, type VerifyFileOperation } from "../../api";
import { ActionButton } from "../../components/ActionButton";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { PasswordField } from "../../components/PasswordField";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { MAX_BATCH_FILES, validateBatchFiles } from "../../hooks/useBatchFiles";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { downloadBlob } from "../../lib/download";
import { formatBytes } from "../../lib/format";
import { deriveWorkflowPhase } from "../../lib/workflow";
import { batchVerificationReport, useBatchVerification } from "./useBatchVerification";

export type BatchVerifyWorkflowProps = {
  health: Health;
  inspect?: InspectKeyOperation;
  verify?: VerifyFileOperation;
  save?: (result: DownloadResult) => void;
  onPendingResultsChange?: (pending: boolean) => void;
};

const STATUS_LABELS = {
  queued: "Queued", processing: "Verifying", complete: "Authenticated", failed: "Failed", cancelled: "Cancelled"
};

export function BatchVerifyWorkflow({ health, inspect, verify = verifyFile, save = downloadBlob, onPendingResultsChange }: BatchVerifyWorkflowProps) {
  const [files, setFiles] = useState<File[]>([]);
  const [privateKey, setPrivateKey] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [exported, setExported] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const { items, busy, start, cancel, clear } = useBatchVerification(verify);
  const capability = health.supportsFileVerification === true
    ? health.capabilities.decrypt
    : { available: false, reason: "Restart an updated local service to verify encrypted files." };
  const locked = busy || items.length > 0;
  const inspection = useKeyInspection(capability.available ? privateKey : null, health.maxPemBytes, inspect);
  const keyError = privateKey && privateKey.size > health.maxPemBytes
    ? `This key file exceeds the ${formatBytes(health.maxPemBytes)} limit.` : null;
  const supportedKey = inspection.result?.ok && inspection.result.keyInfo.key_type === "private" &&
    inspection.result.keyInfo.private_key_encrypted === true && Boolean(inspection.result.keyInfo.kem);
  const validationError = validateBatchFiles(files, health.maxEncryptedFileBytes, "verify");
  const readinessReason = validationError || (!privateKey ? "Choose a private key." : keyError) ||
    (inspection.loading ? "Inspecting private key." : inspection.error ? "The private key could not be inspected." :
      !supportedKey ? "Choose a supported encrypted private key." : !password ? "Enter the private key password." : null);
  const canStart = capability.available && !locked && !readinessReason;
  const authenticatedCount = items.filter((item) => item.status === "complete").length;
  const failedCount = items.filter((item) => item.status === "failed").length;
  const cancelledCount = items.filter((item) => item.status === "cancelled").length;
  const processedCount = authenticatedCount + failedCount + cancelledCount;
  const pending = busy || (items.length > 0 && !exported);
  const pendingCallback = useRef(onPendingResultsChange);
  useLayoutEffect(() => {
    pendingCallback.current = onPendingResultsChange;
    onPendingResultsChange?.(pending);
  }, [onPendingResultsChange, pending]);
  useEffect(() => () => pendingCallback.current?.(false), []);

  function addFiles(selected: File[]) {
    if (locked || selected.length === 0) return;
    const next = [...files, ...selected];
    const error = validateBatchFiles(next, health.maxEncryptedFileBytes, "verify");
    if (error) { setSelectionError(`Files were not added. ${error}`); return; }
    setFiles(next); setSelectionError(null);
  }
  function selectFiles(event: ChangeEvent<HTMLInputElement>) {
    const selected = Array.from(event.currentTarget.files ?? []);
    event.currentTarget.value = "";
    addFiles(selected);
  }
  function dropFiles(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    addFiles(Array.from(event.dataTransfer.files));
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canStart || !privateKey || !inspection.result) return;
    const secret = password;
    setPassword(""); setSelectionError(null); setReportError(null); setExported(false); setCancelling(false);
    start(files, privateKey, secret, { kem: inspection.result.keyInfo.kem,
      maxFileBytes: health.maxFileBytes, maxEncryptedFileBytes: health.maxEncryptedFileBytes });
  }
  function clearBatch() {
    if (busy) return;
    clear(); setFiles([]); setPrivateKey(null); setPassword(""); setSelectionError(null);
    setReportError(null); setExported(false); setCancelling(false);
  }
  function downloadReport() {
    if (busy || items.length === 0) return;
    try {
      save({ filename: "verification-report.json", blob: new Blob([JSON.stringify(batchVerificationReport(items), null, 2)], { type: "application/json" }) });
      setExported(true); setReportError(null);
    } catch {
      setReportError("The report download could not start. Try downloading the report again.");
    }
  }

  return (
    <WorkflowLayout title="Verify multiple files" description="Authenticate a group of encrypted files with one private key, without downloading plaintext."
      capability={capability} busy={busy || inspection.loading}
      phase={deriveWorkflowPhase({ ready: canStart || items.length > 0, complete: items.length > 0 && authenticatedCount === items.length })}>
      {capability.available && <form className="decryption-form" onSubmit={submit}>
        <div className="file-picker-field">
          <label className={files.length ? "file-picker file-picker-selected" : "file-picker"} htmlFor="batch-verify-files"
            onDragOver={(event) => event.preventDefault()} onDrop={dropFiles}>
            <span className="file-picker-label">Files to verify</span>
            <span className="file-picker-prompt">Choose files or drop them here</span>
            <span className="file-picker-selection">{files.length
              ? `${files.length} files · ${formatBytes(files.reduce((sum, file) => sum + file.size, 0))}` : "No files selected"}</span>
            <input id="batch-verify-files" aria-label="Files to verify" type="file" multiple accept=".pqc,application/octet-stream"
              className="file-picker-input" disabled={locked} onChange={selectFiles}
              aria-describedby={`batch-verify-limits${selectionError ? " batch-verify-error" : ""}`} aria-invalid={selectionError ? true : undefined} />
          </label>
          <p className="field-hint" id="batch-verify-limits">Up to {MAX_BATCH_FILES} files and {formatBytes(health.maxEncryptedFileBytes)} total. Files are verified one at a time.</p>
          {selectionError && <p className="field-error" id="batch-verify-error" role="alert">{selectionError}</p>}
        </div>
        {!items.length && files.length > 0 && <ul aria-label="Selected files" className="batch-file-list">
          {files.map((file, index) => <li key={index}>
            <span className="batch-file-name">{file.name}<small>{formatBytes(file.size)}</small></span>
            <button type="button" aria-label={`Remove ${file.name}`} disabled={locked} onClick={() => {
              if (locked) return;
              setFiles((current) => current.filter((_, position) => position !== index)); setSelectionError(null);
            }}>Remove</button>
          </li>)}
        </ul>}
        <FilePicker id="batch-verify-key" label="Private key" file={privateKey} disabled={locked} error={keyError ?? undefined}
          accept=".pem,application/x-pem-file" hint={`Encrypted private PEM key, up to ${formatBytes(health.maxPemBytes)}`}
          onFile={(file) => { if (!locked) { setPrivateKey(file); setPassword(""); } }} />
        {supportedKey && <p>Supported encrypted private key; each file is authenticated separately</p>}
        <PasswordField id="batch-verify-password" label="Private key password" autoComplete="current-password" value={password}
          disabled={locked} onChange={(value) => { if (!locked) setPassword(value); }} />
        <p>Verification authenticates each file in the local service and discards its plaintext. No decrypted file is returned. Authentication does not identify the sender.</p>
        {!locked && readinessReason && <p className="workflow-readiness-reason" role="status">{readinessReason}</p>}
        {!items.length && <ActionButton type="submit" disabled={!canStart} busyLabel="Verifying batch">Verify batch</ActionButton>}
        {busy && <button type="button" disabled={cancelling} onClick={() => { setCancelling(true); cancel(); }}>
          {cancelling ? "Cancelling batch" : "Cancel batch"}
        </button>}
      </form>}
      {items.length > 0 && <section className="batch-results" aria-label="Batch verification results">
        <h2>{busy ? "Verifying batch" : "Batch verification results"}</h2>
        <p role="status" aria-live="polite">{processedCount} of {items.length} files processed · {authenticatedCount} authenticated · {failedCount} failed · {cancelledCount} cancelled</p>
        {cancelling && busy && <Notice kind="info">Cancellation requested. Completed authentication reports remain available.</Notice>}
        <ul className="batch-file-list" aria-label="File verification results">
          {items.map((item) => <li key={item.id}><div className="batch-file-name">
            <strong>{item.file.name}</strong><span>{STATUS_LABELS[item.status]}</span>
            {item.result && <><small>{item.result.bytesVerified.toLocaleString()} bytes authenticated · Format {item.result.formatVersion} · {item.result.kem}</small>
              <span className="fingerprint">{item.result.publicKeyFingerprint}</span></>}
            {item.error && <p className="field-error" role="alert">{item.error}</p>}
          </div></li>)}
        </ul>
        <p>The JSON report includes filenames and recipient fingerprints. It is an unsigned local summary, not proof against later file changes or proof of who sent a file.</p>
        <button type="button" disabled={busy} onClick={downloadReport}>Download verification report</button>
        {exported && <p role="status">Report download started. The browser controls whether it finishes.</p>}
        {reportError && <Notice kind="error">{reportError}</Notice>}
        <button type="button" disabled={busy} onClick={clearBatch}>Clear batch</button>
      </section>}
    </WorkflowLayout>
  );
}
