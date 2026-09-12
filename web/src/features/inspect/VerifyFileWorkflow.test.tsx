import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type EncryptedFileInspection, type FileVerification } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { VerifyFileWorkflow } from "./VerifyFileWorkflow";

const password = "correct horse battery staple";
const inspection: EncryptedFileInspection = {
  ok: true, authenticated: false,
  metadata: { kem: READY_HEALTH.kem, formatVersion: 4, totalBytes: 1400, headerBytes: 1200,
    kemCiphertextBytes: 1088, x25519CiphertextBytes: 32, encryptedPayloadBytes: 200 }
};
const verified: FileVerification = {
  ok: true, verified: true, kem: READY_HEALTH.kem, formatVersion: 4,
  bytesVerified: 0, publicKeyFingerprint: `QE1-SHA3-256:${"a".repeat(64)}`
};
const inspectPrivate = () => vi.fn().mockResolvedValue({
  ok: true, keyInfo: { key_type: "private", private_key_encrypted: true, kem: READY_HEALTH.kem }, display: {}
});
async function selectFile(user: ReturnType<typeof userEvent.setup>, name = "message.pqc") {
  await user.upload(screen.getByLabelText("Encrypted file", { exact: true }), new File(["ciphertext"], name));
}
async function prepare(user: ReturnType<typeof userEvent.setup>) {
  await selectFile(user);
  await screen.findByRole("region", { name: "Encrypted file metadata" });
  await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["encrypted PEM"], "private.pem"));
  await screen.findByText("Supported encrypted private key");
  await user.type(screen.getByLabelText("Private key password", { exact: true }), password);
}

describe("VerifyFileWorkflow", () => {
  it("requires advertised support and allows metadata inspection without the native backend", async () => {
    const inspectFile = vi.fn().mockResolvedValue(inspection);
    const { rerender } = render(<VerifyFileWorkflow health={{ ...READY_HEALTH, supportsFileVerification: undefined }} />);
    expect(screen.queryByLabelText("Encrypted file")).not.toBeInTheDocument();
    rerender(<VerifyFileWorkflow health={{ ...READY_HEALTH, backendReady: false,
      capabilities: { ...READY_HEALTH.capabilities, decrypt: { available: false, reason: "Backend unavailable" } }
    }} inspectFile={inspectFile} inspectKey={inspectPrivate()} />);
    await prepare(userEvent.setup());
    expect(screen.getByText("Metadata only — not authenticated")).toBeVisible();
    expect(screen.getByText("Verification unavailable")).toBeVisible();
    expect(screen.getByRole("button", { name: "Verify file" })).toBeDisabled();
  });

  it("rejects oversized files before uploading and suppresses stale metadata after selection changes", async () => {
    const user = userEvent.setup();
    let resolve!: (value: EncryptedFileInspection) => void;
    const inspectFile = vi.fn().mockReturnValue(new Promise<EncryptedFileInspection>((accept) => { resolve = accept; }));
    render(<VerifyFileWorkflow health={{ ...READY_HEALTH, maxEncryptedFileBytes: 12 }} inspectFile={inspectFile} />);
    await selectFile(user);
    await user.upload(screen.getByLabelText("Encrypted file", { exact: true }), new File(["oversized ciphertext"], "large.pqc"));
    expect(inspectFile.mock.calls[0][1].aborted).toBe(true);
    await act(async () => resolve(inspection));
    expect(inspectFile).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("region", { name: "Encrypted file metadata" })).not.toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("exceeds");
  });

  it.each([
    { key_type: "public", kem: READY_HEALTH.kem },
    { key_type: "private", private_key_encrypted: false, kem: READY_HEALTH.kem },
    { key_type: "private", private_key_encrypted: true, kem: "ML-KEM-768" }
  ])("rejects an unsuitable or mismatched key (%#)", async (keyInfo) => {
    const user = userEvent.setup();
    render(<VerifyFileWorkflow health={READY_HEALTH} inspectFile={vi.fn().mockResolvedValue(inspection)}
      inspectKey={vi.fn().mockResolvedValue({ ok: true, keyInfo, display: {} })} />);
    await selectFile(user);
    await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["PEM"], "private.pem"));
    await user.type(screen.getByLabelText("Private key password", { exact: true }), password);
    expect(screen.getByRole("alert")).toBeVisible();
    expect(screen.getByRole("button", { name: "Verify file" })).toBeDisabled();
  });

  it("accepts matching legacy algorithms and an authenticated empty file without returning plaintext", async () => {
    const user = userEvent.setup();
    const legacy = "ML-KEM-768";
    let resolve!: (value: FileVerification) => void;
    const verify = vi.fn().mockReturnValue(new Promise<FileVerification>((accept) => { resolve = accept; }));
    render(<VerifyFileWorkflow health={READY_HEALTH}
      inspectFile={vi.fn().mockResolvedValue({ ...inspection, metadata: { ...inspection.metadata, kem: legacy } })}
      inspectKey={vi.fn().mockResolvedValue({ ok: true, keyInfo: { key_type: "private", private_key_encrypted: true, kem: legacy }, display: {} })}
      verify={verify} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Verify file" }));
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Encrypted file", { exact: true })).toBeDisabled();
    expect(verify).toHaveBeenCalledWith(expect.any(File), expect.any(File), password, expect.any(AbortSignal));
    await act(async () => resolve({ ...verified, kem: legacy }));
    expect(await screen.findByText("File authenticated")).toBeVisible();
    expect(screen.getByText("0 bytes authenticated.")).toBeVisible();
    expect(screen.queryByRole("button", { name: /download/i })).not.toBeInTheDocument();
    expect(screen.queryByText("Metadata only — not authenticated")).not.toBeInTheDocument();
    await selectFile(user, "another.pqc");
    expect(screen.queryByText("File authenticated")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
  });

  it.each(["reject", "throw"])("clears credentials and hides backend details on %s", async (mode) => {
    const user = userEvent.setup();
    const failure = new ApiError(500, "verification_failed", "private internals");
    const verify = mode === "throw" ? vi.fn(() => { throw failure; }) : vi.fn().mockRejectedValue(failure);
    render(<VerifyFileWorkflow health={READY_HEALTH} inspectFile={vi.fn().mockResolvedValue(inspection)} inspectKey={inspectPrivate()} verify={verify} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Verify file" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not verify this file");
    expect(screen.getByRole("alert")).not.toHaveTextContent("private internals");
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.queryByText("File authenticated")).not.toBeInTheDocument();
  });

  it("never reports success for an incomplete authentication response", async () => {
    const user = userEvent.setup();
    render(<VerifyFileWorkflow health={READY_HEALTH} inspectFile={vi.fn().mockResolvedValue(inspection)} inspectKey={inspectPrivate()}
      verify={vi.fn().mockResolvedValue({ ...verified, verified: false })} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Verify file" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("complete authentication report");
    expect(screen.queryByText("File authenticated")).not.toBeInTheDocument();
  });

  it("aborts active verification on unmount and ignores a late result", async () => {
    const user = userEvent.setup();
    let resolve!: (value: FileVerification) => void;
    const verify = vi.fn().mockReturnValue(new Promise<FileVerification>((accept) => { resolve = accept; }));
    const { unmount } = render(<VerifyFileWorkflow health={READY_HEALTH} inspectFile={vi.fn().mockResolvedValue(inspection)} inspectKey={inspectPrivate()} verify={verify} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Verify file" }));
    unmount();
    expect(verify.mock.calls[0][3].aborted).toBe(true);
    await act(async () => resolve(verified));
    expect(screen.queryByText("File authenticated")).not.toBeInTheDocument();
  });
});
