import { useCallback, useEffect, useRef, useState } from "react";
import { fetchHealth } from "../api/client";
import type { Health } from "../api/contracts";
import { DecryptWorkflow } from "../features/decrypt/DecryptWorkflow";
import { EncryptWorkflow } from "../features/encrypt/EncryptWorkflow";
import { GenerateKeysWorkflow } from "../features/generate/GenerateKeysWorkflow";
import { InspectKeyWorkflow } from "../features/inspect/InspectKeyWorkflow";
import { AppShell } from "./AppShell";
import type { View } from "./navigation";

const SENSITIVE_RESULT_CONFIRMATION = "Generated keys are still available. Leave this workflow and clear them?";

export default function App() {
  const [activeView, setActiveView] = useState<View>("encrypt");
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [hasGeneratedKeys, setHasGeneratedKeys] = useState(false);
  const healthRequestId = useRef(0);
  const initialHealthRequest = useRef<Promise<Health> | null>(null);

  const loadHealth = useCallback(async (retry = false) => {
    const requestId = healthRequestId.current + 1;
    healthRequestId.current = requestId;
    setHealth(null);
    setHealthError(null);
    const request = retry
      ? fetchHealth()
      : (initialHealthRequest.current ?? (initialHealthRequest.current = fetchHealth()));

    try {
      const nextHealth = await request;
      if (requestId === healthRequestId.current) setHealth(nextHealth);
    } catch {
      if (requestId === healthRequestId.current) {
        setHealthError("The local engine status could not be loaded. Restart the app and try again.");
      }
    }
  }, []);

  useEffect(() => {
    void loadHealth();
    return () => {
      healthRequestId.current += 1;
    };
  }, [loadHealth]);

  function navigate(nextView: View) {
    if (nextView === activeView) return;
    if (activeView === "generate" && hasGeneratedKeys) {
      if (!window.confirm(SENSITIVE_RESULT_CONFIRMATION)) return;
      setHasGeneratedKeys(false);
    }
    setActiveView(nextView);
  }

  if (!health) {
    return (
      <main aria-busy={!healthError || undefined} className="workflow-layout">
        {healthError ? (
          <>
            <h1>Local engine unavailable</h1>
            <p role="alert">{healthError}</p>
            <button onClick={() => void loadHealth(true)} type="button">
              Retry
            </button>
          </>
        ) : (
          <p role="status">Loading local engine status.</p>
        )}
      </main>
    );
  }

  return (
    <AppShell activeView={activeView} health={health} onNavigate={navigate}>
      {activeView === "encrypt" && <EncryptWorkflow health={health} />}
      {activeView === "decrypt" && <DecryptWorkflow health={health} />}
      {activeView === "generate" && (
        <GenerateKeysWorkflow health={health} onSensitiveResultChange={setHasGeneratedKeys} />
      )}
      {activeView === "inspect" && <InspectKeyWorkflow health={health} />}
    </AppShell>
  );
}
