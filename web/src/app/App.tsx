import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { fetchHealth } from "../api/client";
import type { Health } from "../api/contracts";
import { DecryptWorkflow } from "../features/decrypt/DecryptWorkflow";
import { BatchDecryptWorkflow } from "../features/decrypt/BatchDecryptWorkflow";
import { EncryptWorkflow } from "../features/encrypt/EncryptWorkflow";
import { BatchEncryptWorkflow } from "../features/encrypt/BatchEncryptWorkflow";
import { GenerateKeysWorkflow } from "../features/generate/GenerateKeysWorkflow";
import { InspectKeyWorkflow } from "../features/inspect/InspectKeyWorkflow";
import { ChangeKeyPasswordWorkflow } from "../features/keys/ChangeKeyPasswordWorkflow";
import { RecoverPublicKeyWorkflow } from "../features/keys/RecoverPublicKeyWorkflow";
import { VerifyFileWorkflow } from "../features/inspect/VerifyFileWorkflow";
import { AppShell } from "./AppShell";
import type { View } from "./navigation";

const SENSITIVE_RESULT_CONFIRMATION = "Generated keys are still available. Leave this workflow and clear them?";
const BATCH_RESULT_CONFIRMATION = "Encrypted files are waiting to be downloaded. Leave this workflow and clear them?";
const PLAINTEXT_RESULT_CONFIRMATION = "Decrypted files are still available in this tab. Leave this workflow and clear them?";
const UPDATED_KEY_CONFIRMATION = "The updated private key is still available. Leave this workflow and clear it?";

export default function App() {
  const [activeView, setActiveView] = useState<View>("encrypt");
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [hasGeneratedKeys, setHasGeneratedKeys] = useState(false);
  const [hasBatchResults, setHasBatchResults] = useState(false);
  const [hasPlaintextResults, setHasPlaintextResults] = useState(false);
  const [hasUpdatedKey, setHasUpdatedKey] = useState(false);
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

  useLayoutEffect(() => {
    if (!hasGeneratedKeys && !hasBatchResults && !hasPlaintextResults && !hasUpdatedKey) return;

    function warnBeforeUnload(event: BeforeUnloadEvent) {
      event.preventDefault();
      event.returnValue = true;
    }

    window.addEventListener("beforeunload", warnBeforeUnload);
    return () => window.removeEventListener("beforeunload", warnBeforeUnload);
  }, [hasGeneratedKeys, hasBatchResults, hasPlaintextResults, hasUpdatedKey]);

  function navigate(nextView: View) {
    if (nextView === activeView) return;
    if (activeView === "generate" && hasGeneratedKeys) {
      if (!window.confirm(SENSITIVE_RESULT_CONFIRMATION)) return;
      setHasGeneratedKeys(false);
    }
    if (activeView === "batch-encrypt" && hasBatchResults) {
      if (!window.confirm(BATCH_RESULT_CONFIRMATION)) return;
      setHasBatchResults(false);
    }
    if (activeView === "batch-decrypt" && hasPlaintextResults) {
      if (!window.confirm(PLAINTEXT_RESULT_CONFIRMATION)) return;
      setHasPlaintextResults(false);
    }
    if (activeView === "change-password" && hasUpdatedKey) {
      if (!window.confirm(UPDATED_KEY_CONFIRMATION)) return;
      setHasUpdatedKey(false);
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
      {activeView === "batch-encrypt" && (
        <BatchEncryptWorkflow health={health} onPendingResultsChange={setHasBatchResults} />
      )}
      {activeView === "decrypt" && <DecryptWorkflow health={health} />}
      {activeView === "batch-decrypt" && (
        <BatchDecryptWorkflow health={health} onPendingResultsChange={setHasPlaintextResults} />
      )}
      {activeView === "generate" && (
        <GenerateKeysWorkflow health={health} onSensitiveResultChange={setHasGeneratedKeys} />
      )}
      {activeView === "inspect" && <InspectKeyWorkflow health={health} />}
      {activeView === "verify-file" && <VerifyFileWorkflow health={health} />}
      {activeView === "recover-public" && <RecoverPublicKeyWorkflow health={health} />}
      {activeView === "change-password" && (
        <ChangeKeyPasswordWorkflow health={health} onSensitiveResultChange={setHasUpdatedKey} />
      )}
    </AppShell>
  );
}
