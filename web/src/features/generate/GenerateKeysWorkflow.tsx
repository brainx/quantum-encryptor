import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { generateKeys, type GenerateKeysOperation, type GeneratedKeys, type Health } from "../../api";
import { isAbortError, safeOperationError } from "../../api/errors";
import { ActionButton } from "../../components/ActionButton";
import { Notice } from "../../components/Notice";
import { PasswordField } from "../../components/PasswordField";
import { TechnicalDetails } from "../../components/TechnicalDetails";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { downloadText } from "../../lib/download";
import { deriveWorkflowPhase } from "../../lib/workflow";
import { passwordPolicyChecks } from "./passwordPolicy";

export type GenerateKeysWorkflowProps = {
  health: Health;
  generate?: GenerateKeysOperation;
  onSensitiveResultChange?: (present: boolean) => void;
};

type GeneratedKeyState = Omit<GeneratedKeys, "publicPem" | "privatePem"> & {
  publicPem: string | null;
  privatePem: string | null;
};

function privateKeyFormatVersion(privatePem: string | null | undefined): string | null {
  if (!privatePem) return null;
  return privatePem.match(/^PQC-Key-Format:\s*(\d+)\s*$/m)?.[1] ?? "Not declared";
}

export function GenerateKeysWorkflow({ health, generate = generateKeys, onSensitiveResultChange }: GenerateKeysWorkflowProps) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [generatedKeys, setGeneratedKeys] = useState<GeneratedKeyState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mountedRef = useRef(true);
  const requestIdRef = useRef(0);
  const inFlightRef = useRef(false);
  const abortControllerRef = useRef<AbortController | null>(null);
  const sensitiveResultChangeRef = useRef(onSensitiveResultChange);
  const capability = health.capabilities.generate;
  const checks = useMemo(
    () => passwordPolicyChecks(password, confirmation, health.passwordPolicy),
    [confirmation, health.passwordPolicy, password]
  );
  const policySatisfied = checks.every((check) => check.met);
  const hasGeneratedKeys = Boolean(generatedKeys?.publicPem && generatedKeys.privatePem);
  const canGenerate = capability.available && policySatisfied && !busy && !hasGeneratedKeys;
  const phase = deriveWorkflowPhase({
    ready: capability.available && policySatisfied,
    complete: hasGeneratedKeys
  });

  useEffect(() => {
    sensitiveResultChangeRef.current = onSensitiveResultChange;
  }, [onSensitiveResultChange]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      requestIdRef.current += 1;
      inFlightRef.current = false;
      abortControllerRef.current?.abort();
      abortControllerRef.current = null;
      sensitiveResultChangeRef.current?.(false);
    };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canGenerate || hasGeneratedKeys || inFlightRef.current) return;

    const requestId = requestIdRef.current + 1;
    const controller = new AbortController();
    requestIdRef.current = requestId;
    inFlightRef.current = true;
    abortControllerRef.current = controller;
    setBusy(true);
    setError(null);

    try {
      const result = await generate(password, controller.signal);
      if (!mountedRef.current || requestId !== requestIdRef.current) return;
      if (!result.ok) {
        setError("Could not generate keys. Check the password requirements and try again.");
        return;
      }
      setGeneratedKeys(result);
      setPassword("");
      setConfirmation("");
      sensitiveResultChangeRef.current?.(true);
    } catch (caught: unknown) {
      if (!mountedRef.current || requestId !== requestIdRef.current) return;
      if (controller.signal.aborted || isAbortError(caught)) return;
      setError(safeOperationError(caught, "Could not generate keys. Check the password requirements and try again."));
    } finally {
      if (requestId === requestIdRef.current) inFlightRef.current = false;
      if (abortControllerRef.current === controller) abortControllerRef.current = null;
      if (mountedRef.current && requestId === requestIdRef.current) {
        setBusy(false);
      }
    }
  }

  function clearGeneratedKeys() {
    setGeneratedKeys((current) =>
      current
        ? {
            ...current,
            publicPem: null,
            privatePem: null
          }
        : null
    );
    sensitiveResultChangeRef.current?.(false);
  }

  return (
    <WorkflowLayout
      busy={busy}
      capability={capability}
      description="Create a public key to share and an encrypted private key to keep."
      phase={phase}
      title="Generate keys"
    >
      <Notice kind="warning" title="Keep your password safe">
        Your private key password cannot be recovered. Save it in a secure password manager before generating keys.
      </Notice>

      {capability.available && !hasGeneratedKeys && (
        <form className="generate-keys-form" onSubmit={submit}>
          <PasswordField
            autoComplete="new-password"
            describedBy="generate-password-requirements"
            disabled={busy}
            id="generate-private-key-password"
            label="Private key password"
            onChange={(value) => {
              if (!busy) setPassword(value);
            }}
            value={password}
          />
          <PasswordField
            autoComplete="new-password"
            describedBy="generate-password-requirements"
            disabled={busy}
            id="generate-private-key-password-confirmation"
            label="Confirm private key password"
            onChange={(value) => {
              if (!busy) setConfirmation(value);
            }}
            value={confirmation}
          />
          <ul aria-label="Password requirements" className="password-policy" id="generate-password-requirements">
            {checks.map((check) => (
              <li className={check.met ? "password-policy-met" : undefined} key={check.label}>
                <span aria-hidden="true">{check.met ? "✓" : "○"}</span>
                {check.label}
              </li>
            ))}
          </ul>
          <ActionButton busy={busy} busyLabel="Generating key pair" disabled={!canGenerate} type="submit">
            Generate key pair
          </ActionButton>
        </form>
      )}

      {error && <Notice kind="error" title="Key generation failed">{error}</Notice>}

      {hasGeneratedKeys && generatedKeys && (
        <section aria-label="Generated key downloads" className="generated-key-downloads">
          <Notice kind="success" title="Key pair generated">
            Save both files now. The app keeps this generated result in this tab, and you may lose it if you clear it, reload, or leave the page. The public key is safe to share; keep the encrypted private key and password secure.
          </Notice>
          <div className="generated-key-download-actions">
            <button
              aria-label="Download public key"
              onClick={() => downloadText(generatedKeys.publicFilename, generatedKeys.publicPem!)}
              type="button"
            >
              <span>Public key</span>
              <strong>{generatedKeys.publicFilename}</strong>
            </button>
            <button
              aria-label="Download encrypted private key"
              onClick={() => downloadText(generatedKeys.privateFilename, generatedKeys.privatePem!)}
              type="button"
            >
              <span>Encrypted private key</span>
              <strong>{generatedKeys.privateFilename}</strong>
            </button>
          </div>
          <ActionButton busyLabel="Clearing generated keys" onClick={clearGeneratedKeys} type="button">
            Clear generated keys
          </ActionButton>
        </section>
      )}

      <TechnicalDetails>
        <dl className="metadata-list">
          <div>
            <dt>Hybrid suite</dt>
            <dd>{health.kem}</dd>
          </div>
          {generatedKeys?.privatePem && (
            <div>
              <dt>Private key format version</dt>
              <dd>{privateKeyFormatVersion(generatedKeys.privatePem)}</dd>
            </div>
          )}
          <div>
            <dt>Password KDF</dt>
            <dd>scrypt</dd>
          </div>
          <div>
            <dt>Password requirements</dt>
            <dd>{health.passwordPolicy.minChars} or more characters and {health.passwordPolicy.minUniqueChars} or more unique characters</dd>
          </div>
        </dl>
      </TechnicalDetails>
    </WorkflowLayout>
  );
}
