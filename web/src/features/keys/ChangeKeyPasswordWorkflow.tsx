import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  changeKeyPassword,
  type ChangedPrivateKey,
  type ChangeKeyPasswordOperation,
  type DownloadResult,
  type Health,
  type InspectKeyOperation
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
import { passwordPolicyChecks } from "../generate/passwordPolicy";

type Props = {
  health: Health;
  inspect?: InspectKeyOperation;
  change?: ChangeKeyPasswordOperation;
  save?: (result: DownloadResult) => void;
  onSensitiveResultChange?: (present: boolean) => void;
};

export function ChangeKeyPasswordWorkflow({
  health, inspect, change = changeKeyPassword, save = downloadBlob, onSensitiveResultChange
}: Props) {
  const [privateKey, setPrivateKey] = useState<File | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [updatedKey, setUpdatedKey] = useState<ChangedPrivateKey | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [downloadStarted, setDownloadStarted] = useState(false);
  const [busy, setBusy] = useState(false);
  const activeRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const callbackRef = useRef(onSensitiveResultChange);
  const capability = {
    available: health.supportsKeyPasswordChange === true,
    reason: "Restart an updated local service to change private-key passwords."
  };
  const { result: inspection, loading: inspecting, error: inspectionError } = useKeyInspection(
    capability.available ? privateKey : null, health.maxPemBytes, inspect
  );
  const checks = passwordPolicyChecks(newPassword, confirmation, health.passwordPolicy);
  const keyError = privateKey && privateKey.size > health.maxPemBytes
    ? `This key file exceeds the ${health.maxPemBytes.toLocaleString()} byte limit.` : null;
  const validPrivateKey = inspection?.ok && inspection.keyInfo.key_type === "private" &&
    inspection.keyInfo.private_key_encrypted === true;
  const locked = busy || updatedKey !== null;
  const ready = capability.available && validPrivateKey && !keyError && !inspecting && !inspectionError &&
    Boolean(currentPassword) && currentPassword !== newPassword && checks.every((check) => check.met);

  useEffect(() => { callbackRef.current = onSensitiveResultChange; }, [onSensitiveResultChange]);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      activeRef.current?.abort();
      callbackRef.current?.(false);
    };
  }, []);

  function clearPasswords() {
    setCurrentPassword("");
    setNewPassword("");
    setConfirmation("");
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || locked || !privateKey || activeRef.current) return;
    const controller = new AbortController();
    activeRef.current = controller;
    setBusy(true);
    setError(null);
    try {
      // The operation captures credentials for this request; remove editable copies immediately.
      const request = change(privateKey, currentPassword, newPassword, controller.signal);
      clearPasswords();
      const result = await request;
      if (!mountedRef.current || controller.signal.aborted) return;
      if (!result.ok || !result.privatePem || !result.privateFilename ||
          result.publicKeyFingerprint?.length !== "QE1-SHA3-256:".length + 64 || !/^QE1-SHA3-256:[0-9a-f]{64}$/.test(result.publicKeyFingerprint)) {
        setError("The local service did not return a complete updated key. Keep your original key and try again.");
        return;
      }
      setUpdatedKey(result);
      callbackRef.current?.(true);
    } catch (caught: unknown) {
      if (!mountedRef.current || controller.signal.aborted || isAbortError(caught)) return;
      setError(safeOperationError(caught, "Could not change the key password. Keep your original key and try again."));
    } finally {
      if (activeRef.current === controller) activeRef.current = null;
      if (mountedRef.current) {
        clearPasswords();
        setBusy(false);
      }
    }
  }

  function download() {
    if (!updatedKey) return;
    try {
      save({ filename: updatedKey.privateFilename, blob: new Blob([updatedKey.privatePem], { type: "application/x-pem-file" }) });
      setDownloadStarted(true);
      setError(null);
    } catch {
      setError("The download could not start. Try downloading the updated key again.");
    }
  }

  function clear() {
    if (busy) return;
    setUpdatedKey(null);
    setPrivateKey(null);
    setError(null);
    setDownloadStarted(false);
    clearPasswords();
    callbackRef.current?.(false);
  }

  return (
    <WorkflowLayout title="Change private key password" description="Protect the same private key with a new password. Your public key and existing encrypted files keep working."
      capability={capability} busy={busy || inspecting} phase={deriveWorkflowPhase({ ready: Boolean(ready), complete: Boolean(updatedKey) })}>
      <Notice kind="warning" title="Keep the original until you verify the updated copy">
        This creates a new encrypted key file. Existing copies still accept the old password; changing this copy does not revoke them.
      </Notice>
      {capability.available && !updatedKey && (
        <form className="change-key-password-form" onSubmit={submit}>
          <FilePicker id="change-password-private-key" label="Private key" file={privateKey}
            accept=".pem,application/x-pem-file" hint={`Encrypted private PEM key, up to ${formatBytes(health.maxPemBytes)}`}
            disabled={locked} error={keyError ?? undefined} onFile={(file) => {
              if (locked) return;
              setPrivateKey(file);
              setError(null);
              clearPasswords();
            }} />
          {inspecting && <p role="status">Inspecting private key.</p>}
          {inspectionError && !keyError && <p role="alert">The private key could not be inspected.</p>}
          {inspection && (validPrivateKey
            ? <p>Supported encrypted private key</p>
            : <p role="alert">Choose a supported encrypted private key.</p>)}
          <PasswordField id="change-password-current" label="Current password" autoComplete="current-password"
            disabled={locked} value={currentPassword} onChange={setCurrentPassword} />
          <PasswordField id="change-password-new" label="New password" autoComplete="new-password"
            describedBy="change-password-policy" disabled={locked} value={newPassword} onChange={setNewPassword} />
          <PasswordField id="change-password-confirm" label="Confirm new password" autoComplete="new-password"
            describedBy="change-password-policy" disabled={locked} value={confirmation} onChange={setConfirmation} />
          <ul aria-label="New password requirements" className="password-policy" id="change-password-policy">
            {checks.map((check) => <li key={check.label} className={check.met ? "password-policy-met" : undefined}>
              <span aria-hidden="true">{check.met ? "✓" : "○"}</span>{check.label}
            </li>)}
            <li className={currentPassword && newPassword && currentPassword !== newPassword ? "password-policy-met" : undefined}>
              New password differs from the current password
            </li>
          </ul>
          <ActionButton type="submit" busy={busy} busyLabel="Changing key password" disabled={!ready || locked}>Change key password</ActionButton>
        </form>
      )}
      {error && <Notice kind="error" title="Password change needs attention">{error}</Notice>}
      {updatedKey && (
        <section className="generated-key-downloads" aria-label="Updated key download">
          <Notice kind="success" title="Private key password changed">
            Download the updated key and test it with your new password before replacing any original copies.
          </Notice>
          <dl className="metadata-list">
            <div><dt>Public key fingerprint</dt><dd>{updatedKey.publicKeyFingerprint}</dd></div>
            <div><dt>Key algorithm</dt><dd>{updatedKey.kem}</dd></div>
          </dl>
          <button type="button" onClick={download}>Download updated private key</button>
          {downloadStarted && <p role="status">Download started. The browser controls whether it finishes.</p>}
          <button type="button" onClick={clear}>Clear updated key</button>
        </section>
      )}
    </WorkflowLayout>
  );
}
