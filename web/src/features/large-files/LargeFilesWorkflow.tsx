import { useEffect, useLayoutEffect, useState, type FormEvent } from "react";
import type { Health, InspectKeyOperation } from "../../api";
import { largeFileOperations, type LargeFileMode, type LargeFileOperations } from "../../api/largeFiles";
import { ActionButton } from "../../components/ActionButton";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { PasswordField } from "../../components/PasswordField";
import { RecipientFingerprintField } from "../../components/RecipientFingerprintField";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { terminalJob, useLargeFileJob } from "../../hooks/useLargeFileJob";
import { formatBytes } from "../../lib/format";
import { isPublicKeyFingerprint, recipientFingerprintError } from "../../lib/recipientFingerprint";

export type LargeFilesWorkflowProps = {
  health: Health;
  inspect?: InspectKeyOperation;
  operations?: LargeFileOperations;
  onSensitiveResultChange?: (pending: boolean) => void;
  onRecoveryChange?: (recoverable: boolean) => void;
};

function runningStatus(phase: string): string {
  if (phase === "encrypting") return "Encrypting file.";
  if (phase === "verifying") return "Authenticating file.";
  if (phase === "decrypting") return "Decrypting authenticated file.";
  return "Preparing operation.";
}

export function LargeFilesWorkflow({ health, inspect, operations = largeFileOperations, onSensitiveResultChange, onRecoveryChange }: LargeFilesWorkflowProps) {
  const [selectedMode, setMode] = useState<LargeFileMode>("encrypt");
  const [file, setFile] = useState<File | null>(null);
  const [key, setKey] = useState<File | null>(null);
  const [expectedFingerprint, setExpectedFingerprint] = useState("");
  const [password, setPassword] = useState("");
  const [downloadRequested, setDownloadRequested] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const job = useLargeFileJob(operations);
  const mode = job.job?.mode ?? selectedMode;
  const limits = health.largeFiles;
  const available = limits?.available === true;
  const maxBytes = mode === "encrypt" ? limits?.maxPlaintextBytes : limits?.maxEncryptedBytes;
  const fileError = file && maxBytes !== undefined && file.size > maxBytes
    ? `This file exceeds the ${formatBytes(maxBytes)} limit.` : null;
  const keyError = key && key.size > health.maxPemBytes ? `This key exceeds the ${formatBytes(health.maxPemBytes)} limit.` : null;
  const inspection = useKeyInspection(available ? key : null, health.maxPemBytes, inspect);
  const publicKey = inspection.result?.ok && inspection.result.keyInfo.key_type === "public" &&
    inspection.result.keyInfo.kem === health.kem && isPublicKeyFingerprint(inspection.result.keyInfo.public_key_fingerprint);
  const privateKey = inspection.result?.ok && inspection.result.keyInfo.key_type === "private" &&
    inspection.result.keyInfo.private_key_encrypted === true;
  const validKey = mode === "encrypt" ? publicKey : privateKey;
  const fingerprint = publicKey ? inspection.result?.keyInfo.public_key_fingerprint : null;
  const fingerprintError = mode === "encrypt"
    ? recipientFingerprintError(expectedFingerprint, fingerprint, health.supportsRecipientFingerprint === true) : null;
  const snapshot = job.job;
  const locked = Boolean(snapshot || job.stage || job.restoring || job.recoveryPending);
  const pending = Boolean(job.stage || job.restoring || job.recoveryPending || (snapshot && (!terminalJob(snapshot) ||
    (snapshot.state === "complete" && snapshot.result && (snapshot.mode === "decrypt" || !downloadRequested)))));
  const capability = {
    available: available || Boolean(snapshot || job.recoveryPending || job.expired),
    reason: "Restart an updated local service to process large files."
  };
  const backendCapability = mode === "encrypt" ? health.capabilities.encrypt : health.capabilities.decrypt;
  const ready = available && backendCapability.available && !locked && file && !fileError && !keyError &&
    validKey && !inspection.loading && !inspection.error && !fingerprintError && (mode === "encrypt" || Boolean(password));
  const terminal = snapshot ? terminalJob(snapshot) : false;
  const progress = job.stage === "uploading" ? job.uploadBytes : snapshot?.processedBytes ?? 0;
  const total = job.stage === "uploading" ? file?.size ?? 0 : snapshot?.totalBytes ?? 0;
  const progressLabel = job.stage === "uploading" ? "Upload progress" : "Operation progress";
  const verification = snapshot?.verification;
  const validVerification = snapshot?.mode === "verify" && verification?.ok && verification.verified === true &&
    Number.isSafeInteger(verification.bytesVerified) && verification.bytesVerified >= 0 &&
    verification.bytesVerified <= (limits?.maxPlaintextBytes ?? 0) && isPublicKeyFingerprint(verification.publicKeyFingerprint);
  const validResult = snapshot?.result && typeof snapshot.result.filename === "string" && snapshot.result.filename.length > 0 &&
    Number.isSafeInteger(snapshot.result.bytes) && snapshot.result.bytes >= 0;

  useLayoutEffect(() => { onSensitiveResultChange?.(pending); }, [onSensitiveResultChange, pending]);
  useLayoutEffect(() => { onRecoveryChange?.(job.canRecover); }, [onRecoveryChange, job.canRecover]);
  useEffect(() => () => onSensitiveResultChange?.(false), [onSensitiveResultChange]);
  useEffect(() => () => onRecoveryChange?.(false), [onRecoveryChange]);

  function selectMode(next: LargeFileMode) {
    if (locked) return;
    setMode(next); setFile(null); setKey(null); setPassword(""); setExpectedFingerprint(""); setDownloadError(null); setDownloadRequested(false);
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || !file || !key) return;
    const secret = password;
    setPassword(""); setDownloadError(null); setDownloadRequested(false);
    void job.start(mode, file, key, secret, mode === "encrypt" ? expectedFingerprint.trim() || undefined : undefined);
  }

  async function clear() {
    if (await job.clear()) {
      setMode(mode);
      setFile(null); setKey(null); setPassword(""); setExpectedFingerprint(""); setDownloadError(null); setDownloadRequested(false);
    }
  }

  function download() {
    if (!snapshot || snapshot.state !== "complete" || !validResult || job.restoring || job.recoveryPending) return;
    try {
      operations.download(snapshot.id);
      setDownloadRequested(true); setDownloadError(null);
    } catch {
      setDownloadError("The download could not be requested. Try again before the temporary file expires.");
    }
  }

  return (
    <WorkflowLayout title="Large files" description="Upload one file to the local service for encryption, decryption, or verification. Temporary files are removed automatically."
      capability={capability} busy={Boolean(job.stage || job.restoring || (snapshot && !terminal))}
      phase={snapshot?.state === "complete" && !job.restoring && !job.recoveryPending ? "complete" : ready || snapshot ? "review" : "select"}>
      {capability.available && <>
        <form className="large-file-form" onSubmit={submit}>
          <label htmlFor="large-file-mode">Operation</label>
          <select id="large-file-mode" value={mode} disabled={locked} onChange={(event) => selectMode(event.target.value as LargeFileMode)}>
            <option value="encrypt">Encrypt</option><option value="decrypt">Decrypt</option><option value="verify">Verify</option>
          </select>
          <FilePicker id="large-file-input" label={mode === "encrypt" ? "File to encrypt" : "Encrypted file"}
            file={file} disabled={locked} error={fileError ?? undefined} hint={`One file, up to ${formatBytes(maxBytes ?? 0)}`}
            onFile={(next) => { if (!locked) { setFile(next); setPassword(""); setDownloadError(null); } }} />
          <FilePicker id="large-file-key" label={mode === "encrypt" ? "Recipient public key" : "Private key"}
            file={key} disabled={locked} error={keyError ?? undefined} accept=".pem,application/x-pem-file"
            hint={`PEM key, up to ${formatBytes(health.maxPemBytes)}`}
            onFile={(next) => { if (!locked) { setKey(next); setPassword(""); setDownloadError(null); } }} />
          {inspection.loading && <p role="status">Inspecting key.</p>}
          {inspection.error && !keyError && <Notice kind="error">The key could not be inspected. Check its format and size.</Notice>}
          {inspection.result && !validKey && <Notice kind="error">{mode === "encrypt"
            ? "Choose a supported public key for the current encryption algorithm, with its complete fingerprint."
            : "Choose a supported encrypted private key."}</Notice>}
          {publicKey && mode === "encrypt" && <section aria-label="Recipient key review">
            <p>Recipient public-key fingerprint</p><p className="fingerprint">{inspection.result?.keyInfo.public_key_fingerprint}</p>
            <p>Compare this complete fingerprint over a separate trusted channel before encrypting.</p>
          </section>}
          {mode === "encrypt" && <RecipientFingerprintField id="large-file-expected-fingerprint" value={expectedFingerprint} actual={fingerprint}
            supported={health.supportsRecipientFingerprint === true} disabled={locked} onChange={setExpectedFingerprint} />}
          {privateKey && mode !== "encrypt" && <p>Supported encrypted private key; match not yet verified</p>}
          {mode !== "encrypt" && <PasswordField id="large-file-password" label="Private key password" autoComplete="current-password"
            disabled={locked} value={password} onChange={(value) => { if (!locked) setPassword(value); }} />}
          {!backendCapability.available && <Notice kind="warning">{backendCapability.reason || "The post-quantum backend is not ready."}</Notice>}
          <label className="recovery-choice">
            <input type="checkbox" checked={job.recoveryEnabled} disabled={locked}
              onChange={(event) => job.setRecoveryEnabled(event.target.checked)} />
            Keep this job available after refresh
          </label>
          <p>This option keeps temporary files on this computer until you clear them or the job expires, including decrypted output. Only a job reference is saved in this tab. Interrupted uploads must be restarted.</p>
          {job.recoveryError && <Notice kind="warning">{job.recoveryError}</Notice>}
          {!locked && <ActionButton type="submit" busyLabel="Starting operation" disabled={!ready}>{mode === "encrypt" ? "Encrypt large file" : mode === "decrypt" ? "Decrypt large file" : "Verify large file"}</ActionButton>}
        </form>
        <p>Files are temporarily stored by the local service. Jobs expire {Math.ceil((limits?.resultTtlSeconds ?? 0) / 60)} minutes after you start the job; recovery does not extend this deadline. {job.canRecover
          ? "You can refresh or return to Large files in this tab to reconnect. Closing the tab may lose its job reference; temporary files remain until cleared or expired."
          : "Leaving this page requests cleanup; automatic expiry handles interrupted connections."}</p>
        {mode === "decrypt" && <p>Decrypted output is stored temporarily on this computer until you clear it or it expires, including after a download is requested.</p>}
        {mode === "verify" && <p>Verification authenticates the complete encrypted file without returning a decrypted file. It does not identify the sender.</p>}
        {(job.stage || snapshot || job.recoveryPending) && <section className="large-file-status" aria-label="Large file job status">
          <p role="status">{job.restoring ? "Reconnecting to the temporary job."
            : job.recoveryPending ? "Waiting to reconnect to the temporary job."
            : job.stage === "reserving" ? "Reserving local service capacity."
            : job.stage === "uploading" ? "Uploading file."
            : job.stage === "starting" ? "Starting operation."
            : job.stage === "cancelling" || snapshot?.state === "cancelling" ? "Cancellation requested. Waiting for the local service to finish cleanup."
            : job.stage === "clearing" ? "Clearing temporary files."
            : snapshot?.state === "running" ? runningStatus(snapshot.phase)
            : snapshot?.state === "cancelled" ? "Operation cancelled."
            : snapshot?.state === "failed" ? "Operation failed."
            : snapshot?.state === "complete" ? "Operation complete."
            : "Waiting for the next operation step."}</p>
          {!terminal && !job.recoveryPending && <><progress aria-label={progressLabel} max={total || 1} value={Math.min(progress, total || 1)} />
            <p>{formatBytes(progress)} of {formatBytes(total)}</p></>}
          {snapshot && <p>Temporary job expires at <time dateTime={snapshot.expiresAt}>{new Date(snapshot.expiresAt).toLocaleTimeString()}</time>.</p>}
          {job.recovered && snapshot && !job.restoring && !job.recoveryPending && <Notice kind="info" title="Job reconnected">The local service confirmed this job’s current status. Your file was not uploaded or processed again.</Notice>}
          {job.recovered && snapshot && ["awaiting_upload", "ready"].includes(snapshot.state) && <Notice kind="warning">Preparation was interrupted. Clear this job, then select the file and key again. Uploads and operation starts are never retried automatically.</Notice>}
          {!terminal && !job.recoveryPending && job.stage !== "clearing" && <button type="button" disabled={job.restoring || job.stage === "cancelling" || snapshot?.state === "cancelling"} onClick={() => void job.cancel()}>Cancel operation</button>}
          {snapshot?.state === "failed" && <Notice kind="error">{snapshot.error?.message || "The local service could not process this file. Check the file and key, then try again."}</Notice>}
          {snapshot?.state === "complete" && !job.restoring && !job.recoveryPending && (snapshot.mode === "verify" ? validVerification
            ? <Notice kind="success" title="File authenticated">{verification?.bytesVerified.toLocaleString()} bytes authenticated.<p>{verification?.publicKeyFingerprint}</p></Notice>
            : <Notice kind="error">The local service did not return a complete authentication report.</Notice>
            : validResult ? <><p>{snapshot.result?.filename} · {formatBytes(snapshot.result?.bytes ?? 0)}</p>
              <button type="button" onClick={download}>Download result</button></>
              : <Notice kind="error">The local service did not return a complete file result.</Notice>)}
          {downloadRequested && <p role="status">Download requested. The browser controls whether it finishes.</p>}
        </section>}
        {job.error && <Notice kind="error">{job.error}</Notice>}
        {downloadError && <Notice kind="error">{downloadError}</Notice>}
        {(snapshot || job.recoveryPending) && job.pollingPaused && <button type="button" onClick={() => void job.refresh()}>Retry status</button>}
        {(terminal || job.expired || (snapshot && (snapshot.state === "awaiting_upload" || snapshot.state === "ready") && !job.stage)) &&
          <button type="button" disabled={job.restoring || job.recoveryPending || job.stage === "clearing"} onClick={() => void clear()}>Clear temporary files</button>}
      </>}
    </WorkflowLayout>
  );
}
