import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  inspectEncryptedFile, verifyFile, type EncryptedFileInspection, type FileVerification,
  type Health, type InspectEncryptedFileOperation, type InspectKeyOperation, type VerifyFileOperation
} from "../../api";
import { isAbortError, safeOperationError } from "../../api/errors";
import { ActionButton } from "../../components/ActionButton";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { PasswordField } from "../../components/PasswordField";
import { TechnicalDetails } from "../../components/TechnicalDetails";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { formatBytes } from "../../lib/format";
import { deriveWorkflowPhase } from "../../lib/workflow";

type Props = {
  health: Health;
  inspectFile?: InspectEncryptedFileOperation;
  inspectKey?: InspectKeyOperation;
  verify?: VerifyFileOperation;
};

export function VerifyFileWorkflow({ health, inspectFile = inspectEncryptedFile, inspectKey, verify = verifyFile }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [privateKey, setPrivateKey] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [inspection, setInspection] = useState<{
    file: File; result: EncryptedFileInspection | null; error: string | null; loading: boolean;
  } | null>(null);
  const [result, setResult] = useState<FileVerification | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const active = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  const supported = health.supportsFileVerification === true;
  const capability = { available: supported, reason: "Restart an updated local service to inspect and verify encrypted files." };
  const fileError = file && file.size > health.maxEncryptedFileBytes
    ? `This encrypted file exceeds the ${formatBytes(health.maxEncryptedFileBytes)} limit.` : null;
  const currentInspection = inspection?.file === file ? inspection : null;
  const metadata = currentInspection?.result?.metadata;
  const inspectingFile = Boolean(file && !fileError && (!currentInspection || currentInspection.loading));
  const keyInspection = useKeyInspection(supported ? privateKey : null, health.maxPemBytes, inspectKey);
  const validPrivate = keyInspection.result?.ok && keyInspection.result.keyInfo.key_type === "private" &&
    keyInspection.result.keyInfo.private_key_encrypted === true;
  const mismatchedAlgorithm = validPrivate && metadata && keyInspection.result?.keyInfo.kem !== metadata.kem;
  const ready = supported && health.capabilities.decrypt.available && metadata && validPrivate &&
    !mismatchedAlgorithm && !keyInspection.loading && !keyInspection.error && !fileError && Boolean(password);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; active.current?.abort(); };
  }, []);

  useEffect(() => {
    if (!file || file.size > health.maxEncryptedFileBytes || !supported) {
      setInspection(null);
      return;
    }
    const controller = new AbortController();
    setInspection({ file, result: null, error: null, loading: true });
    void (async () => {
      try {
        const response = await inspectFile(file, controller.signal);
        if (controller.signal.aborted) return;
        if (!response.ok || response.authenticated !== false || !response.metadata) throw new Error("Invalid inspection result");
        setInspection({ file, result: response, error: null, loading: false });
      } catch (caught) {
        if (controller.signal.aborted || isAbortError(caught)) return;
        setInspection({ file, result: null, error: safeOperationError(caught, "Could not inspect this encrypted file."), loading: false });
      }
    })();
    return () => controller.abort();
  }, [file, health.maxEncryptedFileBytes, inspectFile, supported]);

  function resetResult() { setResult(null); setError(null); }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || busy || active.current || !file || !privateKey) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    resetResult();
    try {
      const request = verify(file, privateKey, password, controller.signal);
      setPassword("");
      const response = await request;
      if (!mounted.current || controller.signal.aborted) return;
      if (!response.ok || response.verified !== true || response.kem !== metadata.kem ||
          response.formatVersion !== metadata.formatVersion || !Number.isSafeInteger(response.bytesVerified) ||
          response.bytesVerified < 0 || response.bytesVerified > health.maxFileBytes ||
          !/^QE1-SHA3-256:[0-9a-f]{64}$/.test(response.publicKeyFingerprint)) {
        setError("The local service did not return a complete authentication report. Try again.");
        return;
      }
      setResult(response);
    } catch (caught) {
      if (!mounted.current || controller.signal.aborted || isAbortError(caught)) return;
      setError(safeOperationError(caught, "Could not verify this file. Check the encrypted file, private key, and password."));
    } finally {
      if (active.current === controller) active.current = null;
      if (mounted.current) { setPassword(""); setBusy(false); }
    }
  }

  return (
    <WorkflowLayout title="Inspect and verify a file" description="Read encrypted-file metadata, then authenticate the complete file using its matching private key."
      capability={capability} busy={busy || inspectingFile || keyInspection.loading}
      phase={deriveWorkflowPhase({ ready: Boolean(ready), complete: Boolean(result) })}>
      {supported && <form className="verify-file-form" onSubmit={submit}>
        <FilePicker id="verify-encrypted-file" label="Encrypted file" file={file} disabled={busy}
          hint={`Supported encrypted file, up to ${formatBytes(health.maxEncryptedFileBytes)}`} error={fileError ?? undefined}
          onFile={(next) => { setFile(next); setPassword(""); resetResult(); }} />
        {inspectingFile && <p role="status">Inspecting encrypted file.</p>}
        {currentInspection?.error && <Notice kind="error" title="File inspection failed">{currentInspection.error}</Notice>}
        {metadata && <section aria-label="Encrypted file metadata">
          {!result && <Notice kind="warning" title="Metadata only — not authenticated">
            The file structure is supported. Its contents and metadata are not trusted until verification succeeds.
          </Notice>}
          <dl className="metadata-list">
            <div><dt>Algorithm</dt><dd>{metadata.kem}</dd></div>
            <div><dt>Format version</dt><dd>{metadata.formatVersion}</dd></div>
            <div><dt>Encrypted file size</dt><dd>{formatBytes(metadata.totalBytes)}</dd></div>
          </dl>
          <TechnicalDetails><dl className="metadata-list">
            <div><dt>Header bytes</dt><dd>{metadata.headerBytes.toLocaleString()}</dd></div>
            <div><dt>KEM ciphertext bytes</dt><dd>{metadata.kemCiphertextBytes.toLocaleString()}</dd></div>
            <div><dt>X25519 ciphertext bytes</dt><dd>{metadata.x25519CiphertextBytes.toLocaleString()}</dd></div>
            <div><dt>Encrypted payload bytes</dt><dd>{metadata.encryptedPayloadBytes.toLocaleString()}</dd></div>
          </dl></TechnicalDetails>
        </section>}
        {!health.capabilities.decrypt.available && <Notice kind="warning" title="Verification unavailable">
          {health.capabilities.decrypt.reason || "The native post-quantum backend is not ready."} Metadata inspection remains available.
        </Notice>}
        <FilePicker id="verify-private-key" label="Private key" file={privateKey} disabled={busy}
          accept=".pem,application/x-pem-file" hint={`Encrypted private PEM key, up to ${formatBytes(health.maxPemBytes)}`}
          error={keyInspection.error ? "The private key could not be inspected. Check its format and size." : undefined}
          onFile={(next) => { setPrivateKey(next); setPassword(""); resetResult(); }} />
        {keyInspection.loading && <p role="status">Inspecting private key.</p>}
        {keyInspection.result && (validPrivate ? <p>Supported encrypted private key</p> : <p role="alert">Choose a supported encrypted private key.</p>)}
        {mismatchedAlgorithm && <p role="alert">The key algorithm does not match this encrypted file.</p>}
        <PasswordField id="verify-private-password" label="Private key password" autoComplete="current-password"
          value={password} disabled={busy} onChange={(value) => { setPassword(value); resetResult(); }} />
        <p>Verification decrypts in the local service's memory and discards the plaintext. No decrypted file is returned or downloaded. Successful authentication does not identify the sender.</p>
        <ActionButton type="submit" busy={busy} busyLabel="Verifying file" disabled={!ready}>Verify file</ActionButton>
      </form>}
      {error && <Notice kind="error" title="Verification failed">{error}</Notice>}
      {result && <section aria-label="File verification result">
        <Notice kind="success" title="File authenticated">{result.bytesVerified.toLocaleString()} bytes authenticated.</Notice>
        <dl className="metadata-list">
          <div><dt>Recipient public-key fingerprint</dt><dd>{result.publicKeyFingerprint}</dd></div>
        </dl>
      </section>}
      {supported && (file || privateKey) && <button type="button" disabled={busy} onClick={() => {
        setFile(null); setPrivateKey(null); setPassword(""); resetResult();
      }}>Clear result</button>}
    </WorkflowLayout>
  );
}
