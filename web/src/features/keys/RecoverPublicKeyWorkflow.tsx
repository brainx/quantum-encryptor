import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  recoverPublicKey,
  type DownloadResult,
  type Health,
  type InspectKeyOperation,
  type RecoverPublicKeyOperation
} from "../../api";
import { isAbortError, safeOperationError } from "../../api/errors";
import { ActionButton } from "../../components/ActionButton";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { PasswordField } from "../../components/PasswordField";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { downloadBlob } from "../../lib/download";
import { formatBytes } from "../../lib/format";
import { deriveWorkflowPhase } from "../../lib/workflow";

export type RecoverPublicKeyWorkflowProps = {
  health: Health;
  inspect?: InspectKeyOperation;
  recover?: RecoverPublicKeyOperation;
  save?: (result: DownloadResult) => void;
};

type RecoveredKey = Awaited<ReturnType<RecoverPublicKeyOperation>>;

function validFingerprint(value: unknown): value is string {
  return typeof value === "string" && value.length === "QE1-SHA3-256:".length + 64 &&
    /^QE1-SHA3-256:[0-9a-f]{64}$/.test(value);
}

function completeRecovery(result: RecoveredKey, compared: boolean): boolean {
  return Boolean(result?.ok && result.publicPem && result.publicFilename && result.kem &&
    validFingerprint(result.publicKeyFingerprint) &&
    (compared ? typeof result.matchesSuppliedPublicKey === "boolean" : result.matchesSuppliedPublicKey === null));
}

export function RecoverPublicKeyWorkflow({
  health,
  inspect,
  recover = recoverPublicKey,
  save = downloadBlob
}: RecoverPublicKeyWorkflowProps) {
  const [privateKey, setPrivateKey] = useState<File | null>(null);
  const [publicKey, setPublicKey] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [recovered, setRecovered] = useState<RecoveredKey | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [downloadStarted, setDownloadStarted] = useState(false);
  const mountedRef = useRef(true);
  const activeRef = useRef<AbortController | null>(null);
  const capability = {
    available: health.supportsPublicKeyRecovery === true,
    reason: "Restart an updated local service to recover public keys."
  };
  const privateInspection = useKeyInspection(capability.available ? privateKey : null, health.maxPemBytes, inspect);
  const publicInspection = useKeyInspection(capability.available ? publicKey : null, health.maxPemBytes, inspect);
  const privateError = privateKey && privateKey.size > health.maxPemBytes
    ? `This private key exceeds the ${health.maxPemBytes.toLocaleString()} byte limit.` : null;
  const publicError = publicKey && publicKey.size > health.maxPemBytes
    ? `This public key exceeds the ${health.maxPemBytes.toLocaleString()} byte limit.` : null;
  const validPrivateKey = privateInspection.result?.ok && privateInspection.result.keyInfo.key_type === "private" &&
    privateInspection.result.keyInfo.private_key_encrypted === true;
  const validPublicKey = publicInspection.result?.ok && publicInspection.result.keyInfo.key_type === "public" &&
    validFingerprint(publicInspection.result.keyInfo.public_key_fingerprint);
  const inspecting = privateInspection.loading || publicInspection.loading;
  const locked = busy || recovered !== null;

  function getReadinessReason(): string | null {
    if (!capability.available) return capability.reason;
    if (!privateKey) return "Choose an encrypted private key.";
    if (privateError) return privateError;
    if (privateInspection.loading) return "Inspecting private key.";
    if (privateInspection.error) return "The private key could not be inspected.";
    if (!validPrivateKey) return "Choose a supported encrypted private key.";
    if (publicError) return publicError;
    if (publicKey && publicInspection.loading) return "Inspecting the comparison public key.";
    if (publicKey && publicInspection.error) return "The comparison key could not be inspected.";
    if (publicKey && !validPublicKey) return "Choose a supported public key for comparison.";
    if (!password) return "Enter the private key password.";
    return null;
  }
  const readinessReason = getReadinessReason();
  const ready = !locked && !readinessReason;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      activeRef.current?.abort();
    };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || !privateKey || activeRef.current) return;
    const controller = new AbortController();
    activeRef.current = controller;
    const requestPassword = password;
    setPassword("");
    setBusy(true);
    setError(null);
    try {
      const result = await recover(privateKey, requestPassword, publicKey, controller.signal);
      if (!mountedRef.current || controller.signal.aborted || activeRef.current !== controller) return;
      if (!completeRecovery(result, publicKey !== null)) {
        setError("The local service did not return a complete recovered public key. Try again.");
        return;
      }
      setRecovered(result);
    } catch (caught: unknown) {
      if (!mountedRef.current || controller.signal.aborted || isAbortError(caught)) return;
      setError(safeOperationError(caught, "Could not recover the public key. Check the private key and password, then try again."));
    } finally {
      if (activeRef.current === controller) activeRef.current = null;
      if (mountedRef.current) {
        setPassword("");
        setBusy(false);
      }
    }
  }

  function download() {
    if (!recovered) return;
    try {
      save({
        filename: recovered.publicFilename,
        blob: new Blob([recovered.publicPem], { type: "application/x-pem-file" })
      });
      setDownloadStarted(true);
      setError(null);
    } catch {
      setError("The download could not start. Try downloading the recovered public key again.");
    }
  }

  function clear() {
    if (busy) return;
    setRecovered(null);
    setPrivateKey(null);
    setPublicKey(null);
    setPassword("");
    setError(null);
    setDownloadStarted(false);
  }

  return (
    <WorkflowLayout
      title="Recover public key"
      description="Recreate a public key from its encrypted private key, and optionally compare an existing public key."
      capability={capability}
      busy={busy || inspecting}
      phase={deriveWorkflowPhase({ ready, complete: recovered !== null })}
    >
      {capability.available && !recovered && (
        <form className="decryption-form" onSubmit={submit}>
          <FilePicker
            id="recover-private-key"
            label="Private key"
            file={privateKey}
            accept=".pem,application/x-pem-file"
            hint={`Encrypted private PEM key, up to ${formatBytes(health.maxPemBytes)}`}
            disabled={locked}
            error={privateError ?? undefined}
            onFile={(file) => {
              if (locked) return;
              setPrivateKey(file);
              setPassword("");
              setError(null);
            }}
          />
          {validPrivateKey && <p>Supported encrypted private key</p>}
          <PasswordField
            id="recover-password"
            label="Private key password"
            autoComplete="current-password"
            disabled={locked}
            value={password}
            onChange={(value) => { if (!locked) { setPassword(value); setError(null); } }}
          />
          <FilePicker
            id="recover-comparison-public-key"
            label="Public key to compare (optional)"
            file={publicKey}
            accept=".pem,application/x-pem-file"
            hint={`Optional public PEM key, up to ${formatBytes(health.maxPemBytes)}`}
            disabled={locked}
            error={publicError ?? undefined}
            onFile={(file) => { if (!locked) { setPublicKey(file); setError(null); } }}
          />
          {publicKey && (
            <button disabled={locked} onClick={() => { if (!locked) { setPublicKey(null); setError(null); } }} type="button">
              Remove comparison key
            </button>
          )}
          {!busy && readinessReason && readinessReason !== privateError && readinessReason !== publicError && (
            <p role="status">{readinessReason}</p>
          )}
          <ActionButton type="submit" busy={busy} busyLabel="Recovering public key" disabled={!ready}>Recover public key</ActionButton>
        </form>
      )}
      {error && <Notice kind="error" title="Public key recovery needs attention">{error}</Notice>}
      {recovered && (
        <section className="generated-key-downloads" aria-label="Recovered public key">
          <Notice kind="success" title="Public key recovered">
            Download the recovered public key to share it. Your encrypted private key remains unchanged.
          </Notice>
          <Notice kind={recovered.matchesSuppliedPublicKey === false ? "warning" : "info"}>
            {recovered.matchesSuppliedPublicKey === true ? "The supplied public key matches this private key."
              : recovered.matchesSuppliedPublicKey === false ? "The supplied public key does not match this private key."
                : "No comparison key supplied."}
          </Notice>
          <dl className="metadata-list">
            <div><dt>Public key fingerprint</dt><dd>{recovered.publicKeyFingerprint}</dd></div>
            <div><dt>Key algorithm</dt><dd>{recovered.kem}</dd></div>
          </dl>
          <p className="field-hint">
            Compare the complete fingerprint over a separate trusted channel. Matching key material does not establish anyone's identity.
          </p>
          <button type="button" onClick={download}>Download public key</button>
          {downloadStarted && <p role="status">Download started. The browser controls whether it finishes.</p>}
          <button type="button" onClick={clear}>Clear result</button>
        </section>
      )}
    </WorkflowLayout>
  );
}
