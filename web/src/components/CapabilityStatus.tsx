import type { Health } from "../api";

type CapabilityStatusProps = {
  health: Health;
  compact?: boolean;
};

const capabilityLabels = {
  encrypt: "Encrypt",
  decrypt: "Decrypt",
  generate: "Generate keys",
  inspect: "Inspect key"
} as const;

function availabilityLabel(available: number): "Ready" | "Limited" | "Unavailable" {
  if (available === 4) return "Ready";
  if (available === 0) return "Unavailable";
  return "Limited";
}

export function CapabilityStatus({ health, compact = false }: CapabilityStatusProps) {
  const available = Object.values(health.capabilities).filter((capability) => capability.available).length;
  const status = availabilityLabel(available);
  const statusClass = status.toLowerCase();

  return (
    <section className={`capability-status capability-status-${statusClass}${compact ? " capability-status-compact" : ""}`}>
      <p
        aria-label={compact ? `Local engine: ${status}` : undefined}
        className="capability-status-summary"
        role="status"
      >
        <span aria-hidden="true" className={`capability-status-dot capability-status-dot-${statusClass}`} />
        {compact ? (
          <strong>{status}</strong>
        ) : (
          <>
            <span>Local engine</span>
            <strong>{status}</strong>
          </>
        )}
      </p>
      <details className="capability-status-details">
        <summary>Capability details</summary>
        <ul>
          {(Object.keys(capabilityLabels) as Array<keyof typeof capabilityLabels>).map((operation) => {
            const capability = health.capabilities[operation];
            const reason = capability.reason || (capability.available ? "Available" : "Unavailable");
            return (
              <li key={operation}>
                <strong>{capabilityLabels[operation]}</strong>
                <span>{reason}</span>
              </li>
            );
          })}
        </ul>
      </details>
    </section>
  );
}
