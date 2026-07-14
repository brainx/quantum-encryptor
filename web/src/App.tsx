import { useEffect, useMemo, useState } from "react";
import {
  ApiError,
  decryptFile,
  DownloadResult,
  encryptFile,
  fetchHealth,
  generateKeys,
  GeneratedKeys,
  Health,
  inspectKey,
  KeyInspectResult
} from "./api";

type View = "encrypt" | "decrypt" | "generate" | "inspect";
type NoticeKind = "info" | "success" | "warning" | "error";
type Notice = { kind: NoticeKind; text: string };

const DEFAULT_HEALTH: Health = {
  ok: true,
  backendReady: false,
  backendMessage: "Checking backend readiness.",
  formatVersion: 4,
  kem: "ML-KEM-768+X25519",
  kemComponent: "ML-KEM-768",
  configuredKem: "ML-KEM-768",
  dem: "AES-256-GCM",
  maxFileBytes: 100 * 1024 * 1024,
  maxEncryptedFileBytes: 101 * 1024 * 1024,
  maxPemBytes: 128 * 1024,
  apiToken: "",
  passwordPolicy: { minChars: 16, minUniqueChars: 5 }
};

const views: Array<{ id: View; label: string; group: "File Workflows" | "Key Management" }> = [
  { id: "encrypt", label: "Encrypt File", group: "File Workflows" },
  { id: "decrypt", label: "Decrypt File", group: "File Workflows" },
  { id: "generate", label: "Generate Keys", group: "Key Management" },
  { id: "inspect", label: "Inspect Key", group: "Key Management" }
];

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB"];
  let value = bytes / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[index]}`;
}

function downloadBlob(result: DownloadResult): void {
  const url = URL.createObjectURL(result.blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = result.filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadText(filename: string, text: string): void {
  downloadBlob({ filename, blob: new Blob([text], { type: "application/x-pem-file" }) });
}

function apiMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Request failed.";
}

function fileTooLarge(file: File | null, maxBytes: number): boolean {
  return !!file && file.size > maxBytes;
}

function sizeNotice(file: File | null, maxBytes: number, label: string): Notice | null {
  if (!fileTooLarge(file, maxBytes)) return null;
  return {
    kind: "error",
    text: `${label} is ${formatBytes(file?.size ?? 0)}. The maximum supported size is ${formatBytes(maxBytes)}.`
  };
}

function suggestedEncryptedName(file: File | null): string {
  if (!file) return "encrypted-file.pqc";
  const dot = file.name.lastIndexOf(".");
  const stem = dot > 0 ? file.name.slice(0, dot) : file.name || "file";
  return `${stem}_encrypted.pqc`;
}

function suggestedDecryptedName(file: File | null): string {
  if (!file) return "decrypted.bin";
  const name = file.name;
  if (name === ".pqc") return "decrypted.bin";
  if (name.endsWith("_encrypted.pqc")) return name.slice(0, -"_encrypted.pqc".length) || "decrypted.bin";
  if (name.endsWith(".pqc")) return `${name.slice(0, -".pqc".length)}_decrypted.bin`;
  const dot = name.lastIndexOf(".");
  if (dot > 0) return `${name.slice(0, dot)}_decrypted${name.slice(dot)}`;
  return `${name}_decrypted.bin`;
}

function useKeyInspection(file: File | null, maxPemBytes: number) {
  const [result, setResult] = useState<KeyInspectResult | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setResult(null);
    setNotice(null);
    if (!file) return;
    if (fileTooLarge(file, maxPemBytes)) {
      setNotice(sizeNotice(file, maxPemBytes, "Key file"));
      return;
    }
    setLoading(true);
    inspectKey(file)
      .then((payload) => {
        if (!cancelled) setResult(payload);
      })
      .catch((error) => {
        if (!cancelled) setNotice({ kind: "error", text: apiMessage(error) });
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [file, maxPemBytes]);

  return { result, notice, loading };
}

function App() {
  const [activeView, setActiveView] = useState<View>("encrypt");
  const [health, setHealth] = useState<Health>(DEFAULT_HEALTH);
  const [healthNotice, setHealthNotice] = useState<Notice | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then((payload) => {
        if (!cancelled) setHealth(payload);
      })
      .catch((error) => {
        if (!cancelled) setHealthNotice({ kind: "error", text: apiMessage(error) });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const readinessNotice = healthNotice ?? {
    kind: health.backendReady ? ("success" as const) : ("warning" as const),
    text: health.backendMessage
  };

  return (
    <div className="app-shell">
      <Sidebar activeView={activeView} health={health} onSelect={setActiveView} />
      <main className="main-panel">
        {activeView === "encrypt" && <EncryptView health={health} readinessNotice={readinessNotice} />}
        {activeView === "decrypt" && <DecryptView health={health} readinessNotice={readinessNotice} />}
        {activeView === "generate" && <GenerateKeysView health={health} readinessNotice={readinessNotice} />}
        {activeView === "inspect" && <InspectKeyView health={health} />}
      </main>
    </div>
  );
}

function Sidebar({ activeView, health, onSelect }: { activeView: View; health: Health; onSelect: (view: View) => void }) {
  return (
    <aside className="sidebar">
      <div className="brand-block">
        <div className="brand-mark" aria-hidden="true">
          QE
        </div>
        <div>
          <h1>Quantum Encryptor</h1>
          <p>Local post-quantum file security</p>
        </div>
      </div>

      {(["File Workflows", "Key Management"] as const).map((group) => (
        <nav className="nav-group" key={group} aria-label={group}>
          <p className="nav-heading">{group}</p>
          {views
            .filter((item) => item.group === group)
            .map((item) => (
              <button
                aria-current={item.id === activeView ? "page" : undefined}
                className={item.id === activeView ? "nav-item active" : "nav-item"}
                key={item.id}
                onClick={() => onSelect(item.id)}
                type="button"
              >
                <span>{item.label}</span>
              </button>
            ))}
        </nav>
      ))}

      <section className="system-card" aria-label="System status">
        <div className={health.backendReady ? "status-dot ready" : "status-dot warning"} />
        <div>
          <p className="system-title">{health.backendReady ? "Backend ready" : "Backend not ready"}</p>
          <p className="system-text">{health.kem}</p>
        </div>
      </section>

      <div className="metadata-grid" aria-label="Configuration">
        <MetaBadge label="Format" value={`v${health.formatVersion}`} />
        <MetaBadge label="Hybrid suite" value={health.kem} />
        <MetaBadge label="DEM" value={health.dem} />
        <MetaBadge label="Max file" value={formatBytes(health.maxFileBytes)} />
      </div>
    </aside>
  );
}

function MetaBadge({ label, value }: { label: string; value: string }) {
  return (
    <div className="meta-badge">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function NoticePanel({ notice }: { notice: Notice | null }) {
  if (!notice) return null;
  return (
    <div
      aria-live={notice.kind === "error" ? "assertive" : "polite"}
      className={`notice ${notice.kind}`}
      role={notice.kind === "error" ? "alert" : "status"}
    >
      {notice.text}
    </div>
  );
}

function WorkflowHeader({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="workflow-header">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
    </div>
  );
}

function Stepper({ steps, activeIndex }: { steps: string[]; activeIndex: number }) {
  return (
    <ol className="stepper" aria-label="Workflow steps">
      {steps.map((step, index) => (
        <li className={index <= activeIndex ? "step active" : "step"} key={step}>
          <span>{index + 1}</span>
          {step}
        </li>
      ))}
    </ol>
  );
}

function FileDrop({
  id,
  label,
  hint,
  accept,
  file,
  onFile
}: {
  id: string;
  label: string;
  hint: string;
  accept?: string;
  file: File | null;
  onFile: (file: File | null) => void;
}) {
  return (
    <label className={file ? "file-drop has-file" : "file-drop"} htmlFor={id}>
      <input
        accept={accept}
        id={id}
        onChange={(event) => onFile(event.target.files?.[0] ?? null)}
        type="file"
      />
      <span className="file-action">Choose file</span>
      <span className="file-copy">
        <strong>{file ? file.name : label}</strong>
        <small>{file ? formatBytes(file.size) : hint}</small>
      </span>
    </label>
  );
}

function FieldRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="field-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function EncryptView({ health, readinessNotice }: { health: Health; readinessNotice: Notice }) {
  const [file, setFile] = useState<File | null>(null);
  const [publicKey, setPublicKey] = useState<File | null>(null);
  const [outputName, setOutputName] = useState("encrypted-file.pqc");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [working, setWorking] = useState(false);
  const [downloadReady, setDownloadReady] = useState(false);
  const keyInspection = useKeyInspection(publicKey, health.maxPemBytes);

  useEffect(() => {
    setOutputName(suggestedEncryptedName(file));
    setDownloadReady(false);
  }, [file]);

  const publicKeyReady = keyInspection.result?.keyInfo.key_type === "public";
  const fileSizeNotice = sizeNotice(file, health.maxFileBytes, "Input file");
  const keySizeNotice = sizeNotice(publicKey, health.maxPemBytes, "Public key file");
  const activeIndex = downloadReady ? 4 : publicKeyReady && outputName ? 3 : file && publicKey ? 2 : file ? 1 : 0;
  const canEncrypt =
    health.backendReady &&
    !!file &&
    !fileSizeNotice &&
    publicKeyReady &&
    !keySizeNotice &&
    !!outputName &&
    !working;

  async function submit() {
    if (!file || !publicKey || !canEncrypt) return;
    setNotice(null);
    setWorking(true);
    try {
      const result = await encryptFile(file, publicKey, outputName);
      downloadBlob(result);
      setDownloadReady(true);
      setNotice({ kind: "success", text: `Encrypted file prepared as ${result.filename}.` });
    } catch (error) {
      setNotice({ kind: "error", text: apiMessage(error) });
    } finally {
      setWorking(false);
    }
  }

  return (
    <section className="workflow">
      <WorkflowHeader title="Encrypt File" subtitle={`Protect files with ${health.kem} and ${health.dem}.`} />
      <NoticePanel notice={readinessNotice} />
      <Stepper steps={["Upload file", "Upload public key", "Review output", "Encrypt", "Download"]} activeIndex={activeIndex} />
      <div className="panel-grid">
        <div className="panel">
          <h3>Inputs</h3>
          <FileDrop id="encrypt-file" label="Select a file to encrypt" hint={`${formatBytes(health.maxFileBytes)} max`} file={file} onFile={setFile} />
          <FileDrop
            accept=".pem"
            id="encrypt-key"
            label="Select recipient public key"
            hint={`${formatBytes(health.maxPemBytes)} max PEM`}
            file={publicKey}
            onFile={setPublicKey}
          />
          <NoticePanel notice={fileSizeNotice} />
          {keyInspection.loading && <NoticePanel notice={{ kind: "info", text: "Inspecting public key." }} />}
          <NoticePanel notice={keyInspection.notice} />
        </div>
        <div className="panel">
          <h3>Review</h3>
          <FieldRow label="File" value={file ? `${file.name} · ${formatBytes(file.size)}` : "Waiting for upload"} />
          <FieldRow label="Public key" value={publicKeyReady ? `${keyInspection.result?.keyInfo.kem} public key` : "Waiting for valid key"} />
          <label className="input-label">
            Output filename
            <input value={outputName} onChange={(event) => setOutputName(event.target.value)} />
          </label>
          <button className="primary-button" disabled={!canEncrypt} onClick={submit} type="button">
            {working ? "Encrypting..." : "Encrypt File"}
          </button>
          <NoticePanel notice={notice} />
        </div>
      </div>
    </section>
  );
}

function DecryptView({ health, readinessNotice }: { health: Health; readinessNotice: Notice }) {
  const [file, setFile] = useState<File | null>(null);
  const [privateKey, setPrivateKey] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [outputName, setOutputName] = useState("decrypted.bin");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [working, setWorking] = useState(false);
  const [downloadReady, setDownloadReady] = useState(false);
  const keyInspection = useKeyInspection(privateKey, health.maxPemBytes);

  useEffect(() => {
    setOutputName(suggestedDecryptedName(file));
    setDownloadReady(false);
  }, [file]);

  const privateKeyReady = keyInspection.result?.keyInfo.key_type === "private";
  const fileSizeNotice = sizeNotice(file, health.maxEncryptedFileBytes, "Encrypted file");
  const keySizeNotice = sizeNotice(privateKey, health.maxPemBytes, "Private key file");
  const activeIndex = downloadReady ? 4 : privateKeyReady && password && outputName ? 3 : file && privateKey ? 2 : file ? 1 : 0;
  const canDecrypt =
    health.backendReady &&
    !!file &&
    !fileSizeNotice &&
    privateKeyReady &&
    !keySizeNotice &&
    !!password &&
    !!outputName &&
    !working;

  async function submit() {
    if (!file || !privateKey || !canDecrypt) return;
    setNotice(null);
    setWorking(true);
    try {
      const result = await decryptFile(file, privateKey, password, outputName);
      downloadBlob(result);
      setDownloadReady(true);
      setPassword("");
      setNotice({ kind: "success", text: `Decrypted file prepared as ${result.filename}.` });
    } catch (error) {
      setNotice({ kind: "error", text: apiMessage(error) });
    } finally {
      setWorking(false);
    }
  }

  return (
    <section className="workflow">
      <WorkflowHeader title="Decrypt File" subtitle="Unlock authenticated .pqc containers with the matching encrypted private key." />
      <NoticePanel notice={readinessNotice} />
      <Stepper steps={["Upload .pqc", "Upload private key", "Enter password", "Decrypt", "Download"]} activeIndex={activeIndex} />
      <div className="panel-grid">
        <div className="panel">
          <h3>Inputs</h3>
          <FileDrop
            accept=".pqc"
            id="decrypt-file"
            label="Select encrypted file"
            hint={`${formatBytes(health.maxEncryptedFileBytes)} max PQC`}
            file={file}
            onFile={setFile}
          />
          <FileDrop
            accept=".pem"
            id="decrypt-key"
            label="Select encrypted private key"
            hint={`${formatBytes(health.maxPemBytes)} max PEM`}
            file={privateKey}
            onFile={setPrivateKey}
          />
          <NoticePanel notice={fileSizeNotice} />
          {keyInspection.loading && <NoticePanel notice={{ kind: "info", text: "Inspecting private key." }} />}
          <NoticePanel notice={keyInspection.notice} />
        </div>
        <div className="panel">
          <h3>Review</h3>
          <FieldRow label="Encrypted file" value={file ? `${file.name} · ${formatBytes(file.size)}` : "Waiting for upload"} />
          <FieldRow label="Private key" value={privateKeyReady ? `${keyInspection.result?.keyInfo.kem} private key` : "Waiting for valid key"} />
          <label className="input-label">
            Private key password
            <input
              autoComplete="current-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          <label className="input-label">
            Output filename
            <input value={outputName} onChange={(event) => setOutputName(event.target.value)} />
          </label>
          <button className="primary-button" disabled={!canDecrypt} onClick={submit} type="button">
            {working ? "Decrypting..." : "Decrypt File"}
          </button>
          <NoticePanel notice={notice} />
        </div>
      </div>
    </section>
  );
}

function GenerateKeysView({ health, readinessNotice }: { health: Health; readinessNotice: Notice }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [working, setWorking] = useState(false);
  const [keys, setKeys] = useState<GeneratedKeys | null>(null);

  const checks = useMemo(
    () => [
      { label: `${health.passwordPolicy.minChars}+ characters`, ok: password.length >= health.passwordPolicy.minChars },
      { label: `${health.passwordPolicy.minUniqueChars}+ unique characters`, ok: new Set(password).size >= health.passwordPolicy.minUniqueChars },
      { label: "Confirmation matches", ok: password.length > 0 && password === confirm }
    ],
    [confirm, health.passwordPolicy.minChars, health.passwordPolicy.minUniqueChars, password]
  );
  const canGenerate = health.backendReady && checks.every((check) => check.ok) && !working;
  const activeIndex = keys ? 4 : canGenerate ? 2 : password || confirm ? 1 : 0;

  async function submit() {
    if (!canGenerate) return;
    setNotice(null);
    setWorking(true);
    setKeys(null);
    try {
      const result = await generateKeys(password);
      setKeys(result);
      setPassword("");
      setConfirm("");
      setNotice({ kind: "success", text: "Key pair generated. Download both PEM files now." });
    } catch (error) {
      setNotice({ kind: "error", text: apiMessage(error) });
    } finally {
      setWorking(false);
    }
  }

  return (
    <section className="workflow">
      <WorkflowHeader title="Generate Keys" subtitle={`Create a password-protected ${health.kem} key pair.`} />
      <NoticePanel notice={readinessNotice} />
      <Stepper steps={["Set password", "Confirm policy", "Generate", "Download public key", "Download private key"]} activeIndex={activeIndex} />
      <div className="panel-grid">
        <div className="panel">
          <h3>Private key password</h3>
          <label className="input-label">
            Password
            <input
              autoComplete="new-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          <label className="input-label">
            Confirm password
            <input
              autoComplete="new-password"
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
            />
          </label>
          <ul className="checklist">
            {checks.map((check) => (
              <li className={check.ok ? "ok" : ""} key={check.label}>
                <span aria-hidden="true" />
                {check.label}
              </li>
            ))}
          </ul>
          <button className="primary-button" disabled={!canGenerate} onClick={submit} type="button">
            {working ? "Generating..." : `Generate ${health.kem} Key Pair`}
          </button>
          <NoticePanel notice={notice} />
        </div>
        <div className="panel result-panel">
          <h3>Downloads</h3>
          {keys ? (
            <div className="download-grid">
              <button className="download-card" onClick={() => downloadText(keys.publicFilename, keys.publicPem)} type="button">
                <span>Public Key</span>
                <strong>{keys.publicFilename}</strong>
              </button>
              <button className="download-card danger" onClick={() => downloadText(keys.privateFilename, keys.privatePem)} type="button">
                <span>Encrypted Private Key</span>
                <strong>{keys.privateFilename}</strong>
              </button>
            </div>
          ) : (
            <p className="empty-copy">Generated PEM files will appear here for immediate download.</p>
          )}
        </div>
      </div>
    </section>
  );
}

function InspectKeyView({ health }: { health: Health }) {
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const keyInspection = useKeyInspection(keyFile, health.maxPemBytes);

  return (
    <section className="workflow">
      <WorkflowHeader title="Inspect Key" subtitle="Review supported PQC PEM metadata without exposing key material." />
      <Stepper steps={["Upload PEM", "Parse metadata", "Review policy"]} activeIndex={keyInspection.result ? 2 : keyFile ? 1 : 0} />
      <div className="panel-grid">
        <div className="panel">
          <h3>Key file</h3>
          <FileDrop
            accept=".pem"
            id="inspect-key"
            label="Select PEM key"
            hint={`${formatBytes(health.maxPemBytes)} max PEM`}
            file={keyFile}
            onFile={setKeyFile}
          />
          {keyInspection.loading && <NoticePanel notice={{ kind: "info", text: "Inspecting key metadata." }} />}
          <NoticePanel notice={keyInspection.notice} />
        </div>
        <div className="panel">
          <h3>Metadata</h3>
          {keyInspection.result ? (
            <div className="metadata-table">
              {Object.entries(keyInspection.result.display).map(([label, value]) => (
                <FieldRow key={label} label={label} value={value} />
              ))}
            </div>
          ) : (
            <p className="empty-copy">Supported key metadata will appear here.</p>
          )}
        </div>
      </div>
    </section>
  );
}

export default App;
