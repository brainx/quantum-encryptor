import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type KeyInspectResult, type RecoveredPublicKey } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { RecoverPublicKeyWorkflow } from "./RecoverPublicKeyWorkflow";

const password = "correct horse battery staple";
const privateFile = () => new File(["ENCRYPTED PRIVATE TEST KEY"], "private.pem");
const publicFile = () => new File(["PUBLIC TEST KEY"], "public.pem");
const recovered: RecoveredPublicKey = {
  ok: true,
  publicPem: "-----BEGIN PQC PUBLIC KEY-----\nPUBLIC TEST MATERIAL\n-----END PQC PUBLIC KEY-----",
  publicFilename: "recipient_public.pem",
  kem: READY_HEALTH.kem,
  publicKeyFingerprint: `QE1-SHA3-256:${"a".repeat(64)}`,
  matchesSuppliedPublicKey: null
};
const privateInspection: KeyInspectResult = {
  ok: true, keyInfo: { key_type: "private", kem: READY_HEALTH.kem, private_key_encrypted: true }, display: {}
};
const publicInspection: KeyInspectResult = {
  ok: true, keyInfo: { key_type: "public", kem: READY_HEALTH.kem, public_key_fingerprint: recovered.publicKeyFingerprint }, display: {}
};
const inspectKeys = () => vi.fn((file: File) => Promise.resolve(file.name === "public.pem" ? publicInspection : privateInspection));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}

async function prepare(user: ReturnType<typeof userEvent.setup>, compare = false) {
  const privateKey = privateFile();
  const publicKey = compare ? publicFile() : null;
  await user.upload(screen.getByLabelText("Private key", { exact: true }), privateKey);
  await screen.findByText("Supported encrypted private key");
  if (publicKey) await user.upload(screen.getByLabelText("Public key to compare (optional)"), publicKey);
  await user.type(screen.getByLabelText("Private key password", { exact: true }), password);
  await waitFor(() => expect(screen.getByRole("button", { name: "Recover public key" })).toBeEnabled());
  return { privateKey, publicKey };
}

describe("RecoverPublicKeyWorkflow", () => {
  it("requires advertised recovery support and works without a native PQC backend", async () => {
    const { rerender } = render(<RecoverPublicKeyWorkflow health={{ ...READY_HEALTH, supportsPublicKeyRecovery: undefined }} />);
    expect(screen.getByText("Restart an updated local service to recover public keys.")).toBeVisible();
    expect(screen.queryByLabelText("Private key", { exact: true })).not.toBeInTheDocument();
    rerender(<RecoverPublicKeyWorkflow health={{ ...READY_HEALTH, backendReady: false }} inspect={inspectKeys()} />);
    await prepare(userEvent.setup());
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeEnabled();
  });

  it.each([
    { key_type: "public", kem: READY_HEALTH.kem, public_key_fingerprint: recovered.publicKeyFingerprint },
    { key_type: "private", kem: READY_HEALTH.kem, private_key_encrypted: false },
    { key_type: "private", kem: READY_HEALTH.kem }
  ])("rejects material that is not an encrypted private key (%#)", async (keyInfo) => {
    const user = userEvent.setup();
    const recover = vi.fn();
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={vi.fn().mockResolvedValue({ ok: true, keyInfo, display: {} })} recover={recover} />);
    await user.upload(screen.getByLabelText("Private key", { exact: true }), privateFile());
    expect(await screen.findByText("Choose a supported encrypted private key.")).toBeVisible();
    await user.type(screen.getByLabelText("Private key password", { exact: true }), password);
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeDisabled();
    expect(recover).not.toHaveBeenCalled();
  });

  it.each(["Private key", "Public key to compare (optional)"])("bounds %s before inspection", async (label) => {
    const inspect = inspectKeys();
    render(<RecoverPublicKeyWorkflow health={{ ...READY_HEALTH, maxPemBytes: 2 }} inspect={inspect} />);
    await userEvent.setup().upload(screen.getByLabelText(label, { exact: true }), new File(["oversized"], "large.pem"));
    expect(screen.getByRole("alert")).toHaveTextContent("exceeds the 2 byte limit");
    expect(inspect).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeDisabled();
  });

  it.each([
    { key_type: "private", kem: READY_HEALTH.kem, private_key_encrypted: true },
    { key_type: "public", kem: READY_HEALTH.kem },
    { key_type: "public", kem: READY_HEALTH.kem, public_key_fingerprint: recovered.publicKeyFingerprint.toUpperCase() }
  ])("rejects invalid comparison material and permits removing it (%#)", async (keyInfo) => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockImplementation((file: File) => Promise.resolve(file.name === "public.pem" ? { ok: true, keyInfo, display: {} } : privateInspection));
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspect} />);
    await prepare(user);
    await user.upload(screen.getByLabelText("Public key to compare (optional)"), publicFile());
    expect(await screen.findByText("Choose a supported public key for comparison.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Remove comparison key" }));
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeEnabled();
  });

  it("waits for the currently selected comparison key and clears credentials when replacing the private key", async () => {
    const user = userEvent.setup();
    const inspection = deferred<KeyInspectResult>();
    const inspect = inspectKeys().mockImplementationOnce(() => Promise.resolve(privateInspection))
      .mockImplementationOnce(() => inspection.promise);
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspect} />);
    await prepare(user);
    await user.upload(screen.getByLabelText("Public key to compare (optional)"), publicFile());
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Remove comparison key" }));
    await act(async () => inspection.resolve({ ...publicInspection, ok: false }));
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeEnabled();
    await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["another key"], "another.pem"));
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeDisabled();
  });

  it("clears the password immediately, locks inputs, and prevents duplicate submissions", async () => {
    const user = userEvent.setup();
    const request = deferred<RecoveredPublicKey>();
    const recover = vi.fn().mockReturnValue(request.promise);
    const save = vi.fn();
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={recover} save={save} />);
    const { privateKey, publicKey } = await prepare(user, true);
    const submit = screen.getByRole("button", { name: "Recover public key" });
    fireEvent.submit(submit.closest("form")!);
    fireEvent.submit(submit.closest("form")!);
    expect(recover).toHaveBeenCalledTimes(1);
    expect(recover).toHaveBeenCalledWith(privateKey, password, publicKey, expect.any(AbortSignal));
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Private key password", { exact: true })).toBeDisabled();
    expect(screen.getByLabelText("Private key", { exact: true })).toBeDisabled();
    expect(screen.getByLabelText("Public key to compare (optional)")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove comparison key" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Recovering public key" })).toBeDisabled();
    await act(async () => request.resolve({ ...recovered, matchesSuppliedPublicKey: true }));
    expect(await screen.findByText("Public key recovered")).toBeVisible();
    expect(screen.queryByLabelText("Private key password", { exact: true })).not.toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
  });

  it.each([
    [true, "The supplied public key matches this private key."],
    [false, "The supplied public key does not match this private key."],
    [null, "No comparison key supplied."]
  ] as const)("reports the %s comparison result without asserting identity", async (matches, message) => {
    const user = userEvent.setup();
    const recover = vi.fn().mockResolvedValue({ ...recovered, matchesSuppliedPublicKey: matches });
    // Legacy key recovery and a different comparison suite are valid; the API decides whether they match.
    const inspect = vi.fn((file: File) => Promise.resolve(file.name === "public.pem" ? publicInspection : {
      ...privateInspection, keyInfo: { ...privateInspection.keyInfo, kem: "Kyber768+X25519-v1" }
    }));
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspect} recover={recover} />);
    await prepare(user, matches !== null);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    expect(await screen.findByText(message)).toBeVisible();
    expect(screen.getByText(recovered.publicKeyFingerprint)).toBeVisible();
    expect(screen.getByText(/Compare the complete fingerprint over a separate trusted channel/)).toHaveTextContent("does not establish anyone's identity");
    expect(screen.queryByText(recovered.publicPem)).not.toBeInTheDocument();
  });

  it("downloads only public material explicitly and retries a failed download without recovering again", async () => {
    const user = userEvent.setup();
    const recover = vi.fn().mockResolvedValue(recovered);
    const save = vi.fn().mockImplementationOnce(() => { throw new Error("private browser detail"); });
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={recover} save={save} />);
    const { privateKey } = await prepare(user);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    const download = await screen.findByRole("button", { name: "Download public key" });
    expect(recover).toHaveBeenCalledWith(privateKey, password, null, expect.any(AbortSignal));
    expect(save).not.toHaveBeenCalled();
    await user.click(download);
    expect(screen.getByRole("alert")).toHaveTextContent("The download could not start. Try downloading the recovered public key again.");
    expect(screen.getByRole("alert")).not.toHaveTextContent("private browser detail");
    expect(screen.queryByText(/Download started/)).not.toBeInTheDocument();
    await user.click(download);
    expect(save).toHaveBeenCalledTimes(2);
    expect(recover).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("Download started. The browser controls whether it finishes.")).toBeVisible();
    const saved = save.mock.calls[1][0];
    expect(saved.filename).toBe(recovered.publicFilename);
    expect(saved.blob.type).toBe("application/x-pem-file");
    const text = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = reject;
      reader.readAsText(saved.blob);
    });
    expect(text).toBe(recovered.publicPem);
  });

  it("clears the result, both selected keys, and all password state", async () => {
    const user = userEvent.setup();
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={vi.fn().mockResolvedValue({ ...recovered, matchesSuppliedPublicKey: true })} />);
    await prepare(user, true);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    await user.click(await screen.findByRole("button", { name: "Clear result" }));
    expect(screen.queryByRole("button", { name: "Download public key" })).not.toBeInTheDocument();
    expect(screen.queryByText("private.pem")).not.toBeInTheDocument();
    expect(screen.queryByText("public.pem")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Private key", { exact: true })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeDisabled();
  });

  it.each(["reject", "throw"])("clears the password after a %s and hides internal failure details", async (mode) => {
    const user = userEvent.setup();
    const error = new ApiError(500, "recovery_failed", "raw private backend detail");
    const recover = mode === "throw" ? vi.fn(() => { throw error; }) : vi.fn().mockRejectedValue(error);
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={recover} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not recover the public key. Check the private key and password, then try again.");
    expect(screen.getByRole("alert")).not.toHaveTextContent("raw private");
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Private key", { exact: true })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Download public key" })).not.toBeInTheDocument();
  });

  it("shows a safe authentication error and requires password entry before another attempt", async () => {
    const user = userEvent.setup();
    const message = "The private key could not be unlocked. Check the key and password.";
    const recover = vi.fn().mockRejectedValue(new ApiError(400, "private_key_failed", message));
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={recover} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByRole("button", { name: "Recover public key" })).toBeDisabled();
    expect(recover).toHaveBeenCalledTimes(1);
  });

  it.each([
    { ok: false },
    { publicPem: "" },
    { publicFilename: "" },
    { publicKeyFingerprint: recovered.publicKeyFingerprint.toUpperCase() },
    { publicKeyFingerprint: `${recovered.publicKeyFingerprint}\n` },
    { matchesSuppliedPublicKey: true }
  ])("rejects incomplete or inconsistent recovery output (%#)", async (patch) => {
    const user = userEvent.setup();
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={vi.fn().mockResolvedValue({ ...recovered, ...patch })} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("did not return a complete recovered public key");
    expect(screen.queryByRole("button", { name: "Download public key" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
  });

  it("does not omit the comparison result when a comparison key was supplied", async () => {
    const user = userEvent.setup();
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={vi.fn().mockResolvedValue(recovered)} />);
    await prepare(user, true);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("did not return a complete recovered public key");
    expect(screen.queryByRole("button", { name: "Download public key" })).not.toBeInTheDocument();
  });

  it("handles request cancellation without a misleading failure and clears the password", async () => {
    const user = userEvent.setup();
    render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={vi.fn().mockRejectedValue(new DOMException("Aborted", "AbortError"))} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Private key password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Private key", { exact: true })).toBeEnabled();
  });

  it("aborts on unmount and suppresses a late recovery response", async () => {
    const user = userEvent.setup();
    const request = deferred<RecoveredPublicKey>();
    const recover = vi.fn().mockReturnValue(request.promise);
    const save = vi.fn();
    const { unmount } = render(<RecoverPublicKeyWorkflow health={READY_HEALTH} inspect={inspectKeys()} recover={recover} save={save} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Recover public key" }));
    unmount();
    expect(recover.mock.calls[0][3].aborted).toBe(true);
    await act(async () => request.resolve(recovered));
    expect(save).not.toHaveBeenCalled();
    expect(screen.queryByText("Public key recovered")).not.toBeInTheDocument();
  });
});
