import type { ReactNode } from "react";

export type NoticeKind = "info" | "success" | "warning" | "error";

export type NoticeProps = {
  kind: NoticeKind;
  title?: string;
  children: ReactNode;
};

export function Notice({ kind, title, children }: NoticeProps) {
  return (
    <div className={`notice notice-${kind}`} role={kind === "error" ? "alert" : "status"}>
      {title && <strong className="notice-title">{title}</strong>}
      <div>{children}</div>
    </div>
  );
}
