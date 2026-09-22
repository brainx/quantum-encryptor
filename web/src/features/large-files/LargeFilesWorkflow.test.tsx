import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { KeyInspectResult } from "../../api";
import type { LargeFileJob, LargeFileMode, LargeFileOperations } from "../../api/largeFiles";
import { READY_HEALTH } from "../../test/fixtures";
import { LargeFilesWorkflow } from "./LargeFilesWorkflow";

const fingerprint = `QE1-SHA3-256:${"a".repeat(64)}`;
const health = { ...READY_HEALTH, largeFiles: { available: true, maxPlaintextBytes: 10, maxEncryptedBytes: 20, resultTtlSeconds: 60 } };
const publicInspection: KeyInspectResult = { ok: true, keyInfo: { key_type: "public", kem: READY_HEALTH.kem, public_key_fingerprint: fingerprint }, display: {} };
const privateInspection: KeyInspectResult = { ok: true, keyInfo: { key_type: "private", kem: READY_HEALTH.kem, private_key_encrypted: true }, display: {} };
const inspect = () => vi.fn((file: File) => Promise.resolve(file.name === "public.pem" ? publicInspection : privateInspection));
function snapshot(mode: LargeFileMode, patch: Partial<LargeFileJob> = {}): LargeFileJob {
  return { id: "job-one", mode, state: "running", phase: "processing", processedBytes: 0, totalBytes: 3,
    expiresAt: new Date(Date.now() + 60_000).toISOString(), ...patch };
}
function operations(mode: LargeFileMode = "encrypt"): LargeFileOperations {
  return {
    create: vi.fn().mockResolvedValue(snapshot(mode, { state: "awaiting_upload" })),
    upload: vi.fn().mockResolvedValue(snapshot(mode, { state: "ready" })),
    start: vi.fn().mockResolvedValue(snapshot(mode, { state: "complete", result: { filename: "result.bin", bytes: 3 } })),
    status: vi.fn().mockResolvedValue(snapshot(mode)), cancel: vi.fn().mockResolvedValue(snapshot(mode, { state: "cancelled" })),
    clear: vi.fn().mockResolvedValue({ ok: true }), download: vi.fn()
  };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}
async function prepare(user: ReturnType<typeof userEvent.setup>, mode: LargeFileMode = "encrypt") {
  if (mode !== "encrypt") await user.selectOptions(screen.getByLabelText("Operation"), mode);
  const file = new File(["abc"], mode === "encrypt" ? "report.txt" : "report.txt.pqc");
  const key = new File(["PEM"], mode === "encrypt" ? "public.pem" : "private.pem");
  await user.upload(screen.getByLabelText(mode === "encrypt" ? "File to encrypt" : "Encrypted file"), file);
  await user.upload(screen.getByLabelText(mode === "encrypt" ? "Recipient public key" : "Private key", { exact: true }), key);
  if (mode === "encrypt") await screen.findByText(fingerprint);
  else {
    await screen.findByText("Supported encrypted private key; match not yet verified");
    await user.type(screen.getByLabelText("Private key password", { exact: true }), "test private password");
  }
  return { file, key };
}

describe("LargeFilesWorkflow", () => {
  it.each([
    ["QE1-SHA3-256:incomplete", true],
    [`QE1-SHA3-256:${"b".repeat(64)}`, true],
    [fingerprint, undefined]
  ])("blocks file reservation for an invalid, mismatched, or unsupported expectation (%s)", async (expected, supportsRecipientFingerprint) => {
    const user = userEvent.setup();
    const api = operations();
    render(<LargeFilesWorkflow health={{ ...health, supportsRecipientFingerprint }} inspect={inspect()} operations={api} />);
    await prepare(user);
    const field = screen.getByLabelText("Expected recipient fingerprint (optional)");
    await user.type(field, expected as string);
    expect(field).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("button", { name: "Encrypt large file" })).toBeDisabled();
    fireEvent.submit(field.closest("form")!);
    expect(api.create).not.toHaveBeenCalled();
    expect(api.upload).not.toHaveBeenCalled();
    expect(api.start).not.toHaveBeenCalled();
  });

  it("retains the submitted expectation through upload and clears it with the temporary job", async () => {
    const user = userEvent.setup();
    const api = operations();
    const upload = deferred<LargeFileJob>();
    vi.mocked(api.upload).mockReturnValue(upload.promise);
    render(<LargeFilesWorkflow health={health} inspect={inspect()} operations={api} />);
    const { key } = await prepare(user);
    const field = screen.getByLabelText("Expected recipient fingerprint (optional)");
    await user.type(field, ` ${fingerprint} `);
    expect(screen.getByText("Expected fingerprint matches the selected public key.")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Encrypt large file" }));
    await waitFor(() => expect(api.upload).toHaveBeenCalled());
    expect(field).toBeDisabled();
    fireEvent.change(field, { target: { value: "" } });
    expect(field).toHaveValue(` ${fingerprint} `);
    expect(api.start).not.toHaveBeenCalled();
    await act(async () => upload.resolve(snapshot("encrypt", { state: "ready" })));
    await screen.findByRole("button", { name: "Download result" });
    expect(api.start).toHaveBeenCalledWith("job-one", key, "", expect.any(AbortSignal), fingerprint);
    expect(api.start).toHaveBeenCalledTimes(1);
    await user.click(screen.getByRole("button", { name: "Clear temporary files" }));
    expect(field).toHaveValue("");
    expect(field).toBeEnabled();
  });

  it("resets the expectation when changing operation mode", async () => {
    const user = userEvent.setup();
    render(<LargeFilesWorkflow health={health} inspect={inspect()} operations={operations()} />);
    await user.type(screen.getByLabelText("Expected recipient fingerprint (optional)"), fingerprint);
    await user.selectOptions(screen.getByLabelText("Operation"), "decrypt");
    expect(screen.queryByLabelText("Expected recipient fingerprint (optional)")).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Operation"), "encrypt");
    expect(screen.getByLabelText("Expected recipient fingerprint (optional)")).toHaveValue("");
  });

  it.each([
    ["encrypting", "Encrypting file."],
    ["verifying", "Authenticating file."],
    ["decrypting", "Decrypting authenticated file."],
    ["unknown private phase", "Preparing operation."]
  ])("labels the %s processing phase without exposing raw server text", async (phase, message) => {
    const user = userEvent.setup();
    const api = operations();
    vi.mocked(api.start).mockResolvedValue(snapshot("encrypt", { phase }));
    render(<LargeFilesWorkflow health={health} inspect={inspect()} operations={api} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Encrypt large file" }));
    expect(await screen.findByText(message)).toBeVisible();
    expect(screen.queryByText("unknown private phase")).not.toBeInTheDocument();
  });

  it("requires advertised support", () => {
    render(<LargeFilesWorkflow health={READY_HEALTH} />);
    expect(screen.getByText("Restart an updated local service to process large files.")).toBeVisible();
    expect(screen.queryByLabelText("Operation")).not.toBeInTheDocument();
  });

  it("enforces separate plaintext and encrypted-input limits", async () => {
    const user = userEvent.setup();
    const api = operations();
    render(<LargeFilesWorkflow health={health} operations={api} inspect={inspect()} />);
    await user.upload(screen.getByLabelText("File to encrypt"), new File(["a".repeat(11)], "large.bin"));
    expect(screen.getByRole("alert")).toHaveTextContent("exceeds the 10 B limit");
    expect(screen.getByRole("button", { name: "Encrypt large file" })).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Operation"), "decrypt");
    await user.upload(screen.getByLabelText("Encrypted file"), new File(["a".repeat(21)], "large.pqc"));
    expect(screen.getByRole("alert")).toHaveTextContent("exceeds the 20 B limit");
    expect(api.create).not.toHaveBeenCalled();
  });

  it.each([
    privateInspection,
    { ...publicInspection, keyInfo: { ...publicInspection.keyInfo, kem: "other-suite" } },
    { ...publicInspection, keyInfo: { key_type: "public", kem: READY_HEALTH.kem } },
    { ...publicInspection, keyInfo: { ...publicInspection.keyInfo, public_key_fingerprint: `${fingerprint}\n` } }
  ])("rejects an invalid recipient key (%#)", async (inspection) => {
    const user = userEvent.setup();
    render(<LargeFilesWorkflow health={health} operations={operations()} inspect={vi.fn().mockResolvedValue(inspection)} />);
    await user.upload(screen.getByLabelText("File to encrypt"), new File(["abc"], "file.txt"));
    await user.upload(screen.getByLabelText("Recipient public key"), new File(["PEM"], "public.pem"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a supported public key");
    expect(screen.getByRole("button", { name: "Encrypt large file" })).toBeDisabled();
  });

  it("rejects public or unencrypted private material for decryption", async () => {
    const user = userEvent.setup();
    const inspection = vi.fn().mockResolvedValueOnce(publicInspection).mockResolvedValueOnce({ ...privateInspection, keyInfo: { ...privateInspection.keyInfo, private_key_encrypted: false } });
    render(<LargeFilesWorkflow health={health} operations={operations("decrypt")} inspect={inspection} />);
    await user.selectOptions(screen.getByLabelText("Operation"), "decrypt");
    await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["PEM"], "public.pem"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a supported encrypted private key");
    await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["PEM"], "unencrypted.pem"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a supported encrypted private key");
    expect(screen.getByRole("button", { name: "Decrypt large file" })).toBeDisabled();
  });

  it("clears passwords immediately, locks inputs, and keeps a plaintext warning after downloading", async () => {
    const user = userEvent.setup();
    const api = operations("decrypt");
    const upload = deferred<LargeFileJob>();
    vi.mocked(api.upload).mockReturnValue(upload.promise);
    const onSensitiveResultChange = vi.fn();
    render(<LargeFilesWorkflow health={health} inspect={inspect()} operations={api} onSensitiveResultChange={onSensitiveResultChange} />);
    const { key } = await prepare(user, "decrypt");
    await user.click(screen.getByRole("button", { name: "Decrypt large file" }));
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Private key password", { exact: true })).toBeDisabled();
    expect(screen.getByLabelText("Operation")).toBeDisabled();
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(true);
    await waitFor(() => expect(api.upload).toHaveBeenCalled());
    act(() => vi.mocked(api.upload).mock.calls[0][2](2, 3));
    expect(screen.getByRole("progressbar", { name: "Upload progress" })).toHaveAttribute("value", "2");
    await act(async () => upload.resolve(snapshot("decrypt", { state: "ready" })));
    expect(await screen.findByRole("button", { name: "Download result" })).toBeEnabled();
    expect(api.start).toHaveBeenCalledWith("job-one", key, "test private password", expect.any(AbortSignal));
    expect(api.download).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Download result" }));
    expect(screen.getByText("Download requested. The browser controls whether it finishes.")).toBeVisible();
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(true);
    await user.click(screen.getByRole("button", { name: "Clear temporary files" }));
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(false);
    expect(screen.getByLabelText("Operation")).toBeEnabled();
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
  });

  it("retains a result after a download failure and retries without reprocessing", async () => {
    const user = userEvent.setup();
    const api = operations();
    vi.mocked(api.download).mockImplementationOnce(() => { throw new Error("private browser detail"); });
    render(<LargeFilesWorkflow health={health} inspect={inspect()} operations={api} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Encrypt large file" }));
    await user.click(await screen.findByRole("button", { name: "Download result" }));
    expect(screen.getByRole("alert")).toHaveTextContent("download could not be requested");
    expect(screen.getByRole("alert")).not.toHaveTextContent("private browser detail");
    await user.click(screen.getByRole("button", { name: "Download result" }));
    expect(api.download).toHaveBeenCalledTimes(2);
    expect(api.start).toHaveBeenCalledTimes(1);
  });

  it("shows cancellation pending until the server confirms cleanup", async () => {
    const user = userEvent.setup();
    const api = operations();
    vi.mocked(api.start).mockResolvedValue(snapshot("encrypt"));
    const cancellation = deferred<LargeFileJob>();
    vi.mocked(api.cancel).mockReturnValue(cancellation.promise);
    render(<LargeFilesWorkflow health={health} inspect={inspect()} operations={api} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Encrypt large file" }));
    await user.click(await screen.findByRole("button", { name: "Cancel operation" }));
    expect(screen.getByText(/Cancellation requested/)).toBeVisible();
    expect(screen.getByLabelText("Operation")).toBeDisabled();
    expect(screen.queryByText("Operation cancelled.")).not.toBeInTheDocument();
    await act(async () => cancellation.resolve(snapshot("encrypt", { state: "cancelled" })));
    expect(await screen.findByText("Operation cancelled.")).toBeVisible();
  });

  it("returns an authentication report for verify without a file download", async () => {
    const user = userEvent.setup();
    const api = operations("verify");
    vi.mocked(api.start).mockResolvedValue(snapshot("verify", { state: "complete", verification: {
      ok: true, verified: true, bytesVerified: 3, kem: health.kem, formatVersion: 4, publicKeyFingerprint: fingerprint
    } }));
    render(<LargeFilesWorkflow health={health} inspect={inspect()} operations={api} />);
    await prepare(user, "verify");
    await user.click(screen.getByRole("button", { name: "Verify large file" }));
    expect(await screen.findByText("File authenticated")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Download result" })).not.toBeInTheDocument();
    expect(api.download).not.toHaveBeenCalled();
  });

  it("clears private credentials when changing mode or selecting another key", async () => {
    const user = userEvent.setup();
    render(<LargeFilesWorkflow health={health} inspect={inspect()} operations={operations("decrypt")} />);
    await prepare(user, "decrypt");
    await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["other"], "other.pem"));
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    await user.type(screen.getByLabelText("Private key password", { exact: true }), "different password");
    await user.selectOptions(screen.getByLabelText("Operation"), "verify");
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByRole("button", { name: "Verify large file" })).toBeDisabled();
  });
});
