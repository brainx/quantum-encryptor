import type { ButtonHTMLAttributes } from "react";

export type ActionButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  busy?: boolean;
  busyLabel: string;
};

export function ActionButton({ busy = false, busyLabel, children, disabled, ...props }: ActionButtonProps) {
  return (
    <button {...props} aria-busy={busy || undefined} disabled={busy || disabled}>
      {busy ? busyLabel : children}
    </button>
  );
}
