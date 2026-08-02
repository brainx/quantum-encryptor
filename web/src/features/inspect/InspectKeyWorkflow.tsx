import { useState } from "react";
import type { Health, InspectKeyOperation, KeyInspectResult } from "../../api";
import { FilePicker } from "../../components/FilePicker";
import { Notice } from "../../components/Notice";
import { TechnicalDetails } from "../../components/TechnicalDetails";
import { WorkflowLayout } from "../../components/WorkflowLayout";
import { useKeyInspection } from "../../hooks/useKeyInspection";
import { deriveWorkflowPhase } from "../../lib/workflow";

export type InspectKeyWorkflowProps = {
  health: Health;
  inspect?: InspectKeyOperation;
};

function summaryLabel(result: KeyInspectResult): string {
  return result.keyInfo.key_type === "public" ? "Public key" : "Encrypted private key";
}

export function InspectKeyWorkflow({ health, inspect }: InspectKeyWorkflowProps) {
  const [file, setFile] = useState<File | null>(null);
  const capability = health.capabilities.inspect;
  const { result, error, loading } = useKeyInspection(
    capability.available ? file : null,
    health.maxPemBytes,
    inspect
  );
  const phase = deriveWorkflowPhase({ ready: capability.available && Boolean(file) && !error, complete: Boolean(result) });

  return (
    <WorkflowLayout
      busy={loading}
      capability={capability}
      description="Check supported key metadata without exposing key material."
      phase={phase}
      title="Inspect a key"
    >
      {capability.available && (
        <FilePicker
          accept=".pem,application/x-pem-file"
          error={error ?? undefined}
          file={file}
          hint={`PEM key file, up to ${health.maxPemBytes.toLocaleString()} bytes`}
          id="inspect-key-file"
          label="Key file"
          onFile={setFile}
        />
      )}
      {loading && <Notice kind="info" title="Inspecting key">Reading supported key metadata locally.</Notice>}
      {result && (
        <section aria-label="Key inspection result" className="key-inspection-result">
          <Notice kind="success" title={summaryLabel(result)}>
            Supported key metadata was read locally.
          </Notice>
          <TechnicalDetails>
            <dl className="metadata-list">
              {Object.entries(result.display).map(([label, value]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
          </TechnicalDetails>
        </section>
      )}
    </WorkflowLayout>
  );
}
