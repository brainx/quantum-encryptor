import type { ReactNode } from "react";

export type TechnicalDetailsProps = {
  children: ReactNode;
};

export function TechnicalDetails({ children }: TechnicalDetailsProps) {
  return (
    <details className="technical-details">
      <summary>Technical details</summary>
      <div className="technical-details-content">{children}</div>
    </details>
  );
}
