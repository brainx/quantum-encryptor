import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  ApiError,
  decryptFile,
  type DecryptFileOperation,
  type DownloadResult,
  type Health,
  type InspectKeyOperation
} from "../../api";
import { isAbortError, safeOperationError } from "../../api/errors";
import { ActionButton } from "../../components/ActionButton";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { PasswordField } from "../../components/PasswordField";
import { TechnicalDetails } from "../../components/TechnicalDetails";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { downloadBlob } from "../../lib/download";
import { suggestedDecryptedName } from "../../lib/filenames";
import { formatBytes } from "../../lib/format";
import { deriveWorkflowPhase } from "../../lib/workflow";

export type DecryptWorkflowProps = {
  health: Health;
  inspect?: InspectKeyOperation;
  decrypt?: DecryptFileOperation;
  save?: (result: DownloadResult) => void;
};

function limitMessage(label: string, maxBytes: number): string {
  return `${label} exceeds the ${maxBytes.toLocaleString()} byte limit.`;
}

function keyFormat(inspection: ReturnType<typeof useKeyInspection>["result"]): string {
  const version = inspection?.keyInfo.private_key_format_version;
  return version === undefined ? "Not available" : String(version);
}

const AUTHENTICATION_ERROR_CODES = new Set(["decryption_failed", "private_key_failed"]);
const AUTHENTICATION_FAILURE =
  "The file could not be authenticated. Check the encrypted file, private key, and password.";

function decryptionError(caught: unknown): string {
  if (caught instanceof ApiError && AUTHENTICATION_ERROR_CODES.has(caught.code)) return AUTHENTICATION_FAILURE;
  return safeOperationError(caught, "The local service could not complete decryption. Try again.");
}

export function DecryptWorkflow({
  health,
  inspect,
  decrypt = decryptFile,
  save = downloadBlob
}: DecryptWorkflowProps) {
  const [file, setFile] = useState<File | null>(null);
  const [privateKey, setPrivateKey] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [outputFilename, setOutputFilename] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [completedFilename, setCompletedFilename] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mountedRef = useRef(true);
  const requestIdRef = useRef(0);
  const inFlightRef = useRef(false);
  const abortControllerRef = useRef<AbortController | null>(null);
  const capability = health.capabilities.decrypt;
  const { result: inspection, error: inspectionError, loading: inspecting } = useKeyInspection(
    capability.available ? privateKey : null,
    health.maxPemBytes,
    inspect
  );
  const fileError = file && file.size > health.maxEncryptedFileBytes
    ? limitMessage("This encrypted file", health.maxEncryptedFileBytes)
    : null;
  const keyError = privateKey && privateKey.size > health.maxPemBytes
    ? limitMessage("This key file", health.maxPemBytes)
    : null;
  const safeInspectionError = inspectionError ? "The private key could not be inspected." : null;

  const readinessReason = useMemo(() => {
    if (!capability.available) return capability.reason;
    if (!file) return "Choose an encrypted file.";
    if (fileError) return fileError;
    if (!privateKey) return "Choose a private key.";
    if (keyError) return keyError;
    if (inspecting) return "Inspecting private key.";
    if (safeInspectionError) return safeInspectionError;
    if (!inspection?.ok) return "The private key could not be inspected.";
    if (inspection.keyInfo.key_type !== "private") return "A private key is required to decrypt a file.";
    if (!password) return "Enter the private key password.";
    if (!outputFilename.trim()) return "Enter an output filename.";
    return null;
  }, [
    capability.available,
    capability.reason,
    file,
    fileError,
    inspection,
    inspecting,
    keyError,
    outputFilename,
    password,
    privateKey,
    safeInspectionError
  ]);
  const canDecrypt = !readinessReason && !busy;
  const phase = deriveWorkflowPhase({
    ready: Boolean(canDecrypt),
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
    setOutputFilename(suggestedDecryptedName(nextFile));
    clearOutcome();
  }

  function selectPrivateKey(nextFile: File | null) {
    if (busy) return;
    setPrivateKey(nextFile);
    clearOutcome();
  }

  function updateOutputFilename(value: string) {
    if (busy) return;
    setOutputFilename(value);
    clearOutcome();
  }

  function updatePassword(value: string) {
    if (busy) return;
    setPassword(value);
    clearOutcome();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canDecrypt || !file || !privateKey || inFlightRef.current) return;

    const requestId = requestIdRef.current + 1;
    const controller = new AbortController();
    requestIdRef.current = requestId;
    inFlightRef.current = true;
    abortControllerRef.current = controller;
    setBusy(true);
    setError(null);
    setCompletedFilename(null);

    try {
      const result = await decrypt(file, privateKey, password, outputFilename.trim(), controller.signal);
      if (!mountedRef.current || requestId !== requestIdRef.current) return;
      setPassword("");
      try {
        save(result);
      } catch {
        setError("The file was decrypted, but the download could not start. Try decrypting it again.");
        return;
      }
      setCompletedFilename(result.filename);
    } catch (caught: unknown) {
      if (!mountedRef.current || requestId !== requestIdRef.current) return;
      if (controller.signal.aborted || isAbortError(caught)) return;
      setError(decryptionError(caught));
    } finally {
      if (requestId === requestIdRef.current) inFlightRef.current = false;
      if (abortControllerRef.current === controller) abortControllerRef.current = null;
      if (mountedRef.current && requestId === requestIdRef.current) setBusy(false);
    }
  }

  const keyClassification = !inspection
    ? null
    : inspection.keyInfo.key_type === "private"
      ? "Supported encrypted private key; match not yet verified"
      : "Public key — not valid for decryption";

  return (
    <WorkflowLayout
      busy={busy || inspecting}
      capability={capability}
      description="Open an authenticated .pqc file with its encrypted private key."
      phase={phase}
      title="Decrypt a file"
    >
      {capability.available && (
        <form className="decryption-form" onSubmit={submit}>
          <FilePicker
            accept=".pqc,application/octet-stream"
            disabled={busy}
            error={fileError ?? undefined}
            file={file}
            hint={`Authenticated PQC file, up to ${formatBytes(health.maxEncryptedFileBytes)}`}
            id="decrypt-file"
            label="Encrypted file"
            onFile={selectFile}
          />
          <FilePicker
            accept=".pem,application/x-pem-file"
            disabled={busy}
            error={keyError ?? undefined}
            file={privateKey}
            hint={`Encrypted private PEM key, up to ${formatBytes(health.maxPemBytes)}`}
            id="decrypt-private-key"
            label="Private key"
            onFile={selectPrivateKey}
          />

          {inspecting && <Notice kind="info" title="Inspecting private key">Checking safe key metadata locally.</Notice>}
          {safeInspectionError && <Notice kind="error" title="Could not inspect private key">{safeInspectionError}</Notice>}

          <section aria-label="Decryption review" className="workflow-review">
            <h2>Review</h2>
            <dl className="review-list">
              <div>
                <dt>Encrypted file</dt>
                <dd>{file ? file.name : "Not selected"}</dd>
              </div>
              <div>
                <dt>Size</dt>
                <dd>{file ? formatBytes(file.size) : "Not selected"}</dd>
              </div>
              <div>
                <dt>Private key</dt>
                <dd>{keyClassification ?? (privateKey ? "Awaiting inspection" : "Not selected")}</dd>
              </div>
            </dl>
            <PasswordField
              autoComplete="current-password"
              disabled={busy}
              id="decrypt-private-key-password"
              label="Private key password"
              onChange={updatePassword}
              value={password}
            />
            <div className="output-filename-field">
              <label htmlFor="decrypt-output-filename">Output filename</label>
              <input
                id="decrypt-output-filename"
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

          <ActionButton busy={busy} busyLabel="Decrypting locally" disabled={!canDecrypt} type="submit">
            Decrypt file
          </ActionButton>
        </form>
      )}

      {error && <Notice kind="error" title="Decryption failed">{error}</Notice>}
      {completedFilename && (
        <Notice kind="success" title="File decrypted">
          Saved {completedFilename}.
        </Notice>
      )}

      <TechnicalDetails>
        <dl className="metadata-list">
          <div>
            <dt>Key format</dt>
            <dd>{keyFormat(inspection)}</dd>
          </div>
          <div>
            <dt>Key KDF</dt>
            <dd>{inspection?.keyInfo.private_key_kdf ?? "Not available"}</dd>
          </div>
          <div>
            <dt>Hybrid suite</dt>
            <dd>{inspection?.keyInfo.kem ?? health.kem}</dd>
          </div>
        </dl>
      </TechnicalDetails>
    </WorkflowLayout>
  );
}
