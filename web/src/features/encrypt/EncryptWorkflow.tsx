import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  encryptFile,
  type DownloadResult,
  type EncryptFileOperation,
  type Health,
  type InspectKeyOperation
} from "../../api";
import { isAbortError, safeOperationError } from "../../api/errors";
import { ActionButton } from "../../components/ActionButton";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { TechnicalDetails } from "../../components/TechnicalDetails";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { downloadBlob } from "../../lib/download";
import { suggestedEncryptedName } from "../../lib/filenames";
import { formatBytes } from "../../lib/format";
import { deriveWorkflowPhase } from "../../lib/workflow";

export type EncryptWorkflowProps = {
  health: Health;
  inspect?: InspectKeyOperation;
  encrypt?: EncryptFileOperation;
  save?: (result: DownloadResult) => void;
};

function limitMessage(label: string, maxBytes: number): string {
  return `${label} exceeds the ${maxBytes.toLocaleString()} byte limit.`;
}

export function EncryptWorkflow({
  health,
  inspect,
  encrypt = encryptFile,
  save = downloadBlob
}: EncryptWorkflowProps) {
  const [file, setFile] = useState<File | null>(null);
  const [publicKey, setPublicKey] = useState<File | null>(null);
  const [outputFilename, setOutputFilename] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [completedFilename, setCompletedFilename] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mountedRef = useRef(true);
  const requestIdRef = useRef(0);
  const inFlightRef = useRef(false);
  const abortControllerRef = useRef<AbortController | null>(null);
  const capability = health.capabilities.encrypt;
  const { result: inspection, error: inspectionError, loading: inspecting } = useKeyInspection(
    capability.available ? publicKey : null,
    health.maxPemBytes,
    inspect
  );
  const fileError = file && file.size > health.maxFileBytes ? limitMessage("This file", health.maxFileBytes) : null;
  const keyError = publicKey && publicKey.size > health.maxPemBytes ? limitMessage("This key file", health.maxPemBytes) : null;
  const safeInspectionError = inspectionError ? "The recipient key could not be inspected." : null;
  const compatiblePublicKey = Boolean(
    inspection?.ok && inspection.keyInfo.key_type === "public" && inspection.keyInfo.kem === health.kem
  );

  const readinessReason = useMemo(() => {
    if (!capability.available) return capability.reason;
    if (!file) return "Choose a file to encrypt.";
    if (fileError) return fileError;
    if (!publicKey) return "Choose the recipient's public key.";
    if (keyError) return keyError;
    if (inspecting) return "Inspecting recipient key.";
    if (safeInspectionError) return safeInspectionError;
    if (!inspection?.ok) return "The recipient key could not be inspected.";
    if (inspection.keyInfo.key_type !== "public") return "A public key is required to encrypt a file.";
    if (inspection.keyInfo.kem !== health.kem) {
      return `This public key uses ${inspection.keyInfo.kem}; encryption requires ${health.kem}.`;
    }
    if (!outputFilename.trim()) return "Enter an output filename.";
    return null;
  }, [
    capability.available,
    capability.reason,
    file,
    fileError,
    health.kem,
    inspection,
    inspecting,
    keyError,
    outputFilename,
    publicKey,
    safeInspectionError
  ]);
  const canEncrypt = !readinessReason && !busy;
  const phase = deriveWorkflowPhase({
    ready: Boolean(canEncrypt),
    complete: Boolean(completedFilename)
  });

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      requestIdRef.current += 1;
      inFlightRef.current = false;
      abortControllerRef.current?.abort();
      abortControllerRef.current = null;
    };
  }, []);

  function clearOutcome() {
    requestIdRef.current += 1;
    setError(null);
    setCompletedFilename(null);
  }

  function selectFile(nextFile: File | null) {
    if (busy) return;
    setFile(nextFile);
    setOutputFilename(suggestedEncryptedName(nextFile));
    clearOutcome();
  }

  function selectPublicKey(nextFile: File | null) {
    if (busy) return;
    setPublicKey(nextFile);
    clearOutcome();
  }

  function updateOutputFilename(value: string) {
    if (busy) return;
    setOutputFilename(value);
    clearOutcome();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canEncrypt || !file || !publicKey || inFlightRef.current) return;

    const requestId = requestIdRef.current + 1;
    const controller = new AbortController();
    requestIdRef.current = requestId;
    inFlightRef.current = true;
    abortControllerRef.current = controller;
    setBusy(true);
    setError(null);
    setCompletedFilename(null);

    try {
      const result = await encrypt(file, publicKey, outputFilename.trim(), controller.signal);
      if (!mountedRef.current || requestId !== requestIdRef.current) return;
      try {
        save(result);
      } catch {
        setError("The file was encrypted, but the download could not start. Try encrypting it again.");
        return;
      }
      setCompletedFilename(result.filename);
    } catch (caught: unknown) {
      if (!mountedRef.current || requestId !== requestIdRef.current) return;
      if (controller.signal.aborted || isAbortError(caught)) return;
      setError(safeOperationError(caught, "Could not encrypt this file. Confirm the recipient key and try again."));
    } finally {
      if (requestId === requestIdRef.current) inFlightRef.current = false;
      if (abortControllerRef.current === controller) abortControllerRef.current = null;
      if (mountedRef.current && requestId === requestIdRef.current) setBusy(false);
    }
  }

  const keyClassification = !inspection
    ? null
    : compatiblePublicKey
      ? "Compatible public key"
      : inspection.keyInfo.key_type === "private"
        ? "Private key — not valid for encryption"
        : "Public key — not compatible";

  return (
    <WorkflowLayout
      busy={busy || inspecting}
      capability={capability}
      description="Protect a file for someone using their public key."
      phase={phase}
      title="Encrypt a file"
    >
      {capability.available && (
        <form className="encryption-form" onSubmit={submit}>
          <FilePicker
            disabled={busy}
            error={fileError ?? undefined}
            file={file}
            hint={`File to protect, up to ${formatBytes(health.maxFileBytes)}`}
            id="encrypt-file"
            label="File to encrypt"
            onFile={selectFile}
          />
          <FilePicker
            accept=".pem,application/x-pem-file"
            disabled={busy}
            error={keyError ?? undefined}
            file={publicKey}
            hint={`Recipient public PEM key, up to ${formatBytes(health.maxPemBytes)}`}
            id="encrypt-public-key"
            label="Recipient public key"
            onFile={selectPublicKey}
          />

          {inspecting && <Notice kind="info" title="Inspecting recipient key">Checking safe key metadata locally.</Notice>}
          {safeInspectionError && <Notice kind="error" title="Could not inspect recipient key">{safeInspectionError}</Notice>}

          <section aria-label="Encryption review" className="workflow-review">
            <h2>Review</h2>
            <dl className="review-list">
              <div>
                <dt>File</dt>
                <dd>{file ? file.name : "Not selected"}</dd>
              </div>
              <div>
                <dt>Size</dt>
                <dd>{file ? formatBytes(file.size) : "Not selected"}</dd>
              </div>
              <div>
                <dt>Recipient key</dt>
                <dd>{keyClassification ?? (publicKey ? "Awaiting inspection" : "Not selected")}</dd>
              </div>
            </dl>
            <div className="output-filename-field">
              <label htmlFor="encrypt-output-filename">Output filename</label>
              <input
                id="encrypt-output-filename"
                disabled={busy}
                onChange={(event) => updateOutputFilename(event.target.value)}
                type="text"
                value={outputFilename}
              />
            </div>
            {readinessReason && !busy && readinessReason !== fileError && readinessReason !== keyError && readinessReason !== safeInspectionError && (
              <p className="workflow-readiness-reason" role="status">{readinessReason}</p>
            )}
          </section>

          <ActionButton busy={busy} busyLabel="Encrypting locally" disabled={!canEncrypt} type="submit">
            Encrypt file
          </ActionButton>
        </form>
      )}

      {error && <Notice kind="error" title="Encryption failed">{error}</Notice>}
      {completedFilename && (
        <Notice kind="success" title="File encrypted">
          Saved {completedFilename}.
        </Notice>
      )}

      <TechnicalDetails>
        <dl className="metadata-list">
          <div>
            <dt>Hybrid suite</dt>
            <dd>{health.kem}</dd>
          </div>
          <div>
            <dt>DEM</dt>
            <dd>{health.dem}</dd>
          </div>
          <div>
            <dt>New file format version</dt>
            <dd>{health.formatVersion}</dd>
          </div>
        </dl>
      </TechnicalDetails>
    </WorkflowLayout>
  );
}
