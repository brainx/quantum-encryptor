import { recipientFingerprintError } from "../lib/recipientFingerprint";

type RecipientFingerprintFieldProps = {
  id: string;
  value: string;
  actual: string | null | undefined;
  supported: boolean;
  disabled: boolean;
  onChange: (value: string) => void;
};

export function RecipientFingerprintField({ id, value, actual, supported, disabled, onChange }: RecipientFingerprintFieldProps) {
  const error = recipientFingerprintError(value, actual, supported);
  const status = error || (value.trim()
    ? actual ? "Expected fingerprint matches the selected public key." : "Waiting for the current recipient key inspection."
    : null);
  return (
    <div className="output-filename-field">
      <label htmlFor={id}>Expected recipient fingerprint (optional)</label>
      <textarea className="recipient-fingerprint-input" id={id} rows={2} wrap="soft" value={value} disabled={disabled} autoComplete="off" autoCapitalize="off" spellCheck={false}
        aria-describedby={`${id}-hint${status ? ` ${id}-status` : ""}`} aria-invalid={error ? true : undefined}
        onChange={(event) => { if (!disabled) onChange(event.target.value); }} />
      <p className="field-hint" id={`${id}-hint`}>
        Paste the complete fingerprint obtained through a separate trusted channel. If supplied, the local service checks it against the public key before encrypting. A match does not verify the recipient's identity.
      </p>
      {status && <p className={error ? "field-error" : "field-hint"} id={`${id}-status`} role="status">{status}</p>}
    </div>
  );
}
