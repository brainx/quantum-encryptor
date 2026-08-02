import { useState } from "react";

export type PasswordFieldProps = {
  id: string;
  label: string;
  value: string;
  autoComplete: "new-password" | "current-password";
  describedBy?: string;
  disabled?: boolean;
  onChange: (value: string) => void;
};

export function PasswordField({ id, label, value, autoComplete, describedBy, disabled = false, onChange }: PasswordFieldProps) {
  const [visible, setVisible] = useState(false);

  return (
    <div className="password-field">
      <label htmlFor={id}>{label}</label>
      <div className="password-field-control">
        <input
          aria-describedby={describedBy}
          autoComplete={autoComplete}
          disabled={disabled}
          id={id}
          onChange={(event) => onChange(event.target.value)}
          type={visible ? "text" : "password"}
          value={value}
        />
        <button aria-label={visible ? "Hide password" : "Show password"} disabled={disabled} onClick={() => setVisible(!visible)} type="button">
          {visible ? "Hide" : "Show"}
        </button>
      </div>
    </div>
  );
}
