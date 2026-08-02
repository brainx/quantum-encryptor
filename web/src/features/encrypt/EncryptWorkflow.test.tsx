import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { EncryptWorkflow } from "./EncryptWorkflow";

function publicKeyInspection() {
  return {
    ok: true,
    keyInfo: { kem: READY_HEALTH.kem, key_type: "public" as const },
    display: { "Key Type": "Public", Algorithm: READY_HEALTH.kem }
  };
}

async function prepareEncryption(user: ReturnType<typeof userEvent.setup>) {
  await user.upload(screen.getByLabelText("File to encrypt"), new File(["report"], "report.pdf"));
  await user.upload(screen.getByLabelText("Recipient public key"), new File(["PEM"], "recipient.pem"));
  await screen.findByText("Compatible public key");
}

describe("EncryptWorkflow", () => {
  it("encrypts with a compatible public key and saves the returned file", async () => {
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const encrypt = vi.fn().mockResolvedValue({
      filename: "report_encrypted.pqc",
      blob: new Blob(["ciphertext"])
    });
    const save = vi.fn();
    const user = userEvent.setup();

    render(<EncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={save} />);

    await user.upload(screen.getByLabelText("File to encrypt"), new File(["report"], "report.pdf"));
    await user.upload(
      screen.getByLabelText("Recipient public key"),
      new File(["PEM"], "recipient.pem", { type: "application/x-pem-file" })
    );

    expect(await screen.findByText("Compatible public key")).toBeVisible();
    expect(screen.getByLabelText("Output filename")).toHaveValue("report_encrypted.pqc");

    await user.click(screen.getByRole("button", { name: "Encrypt file" }));

    await waitFor(() =>
      expect(encrypt).toHaveBeenCalledWith(
        expect.objectContaining({ name: "report.pdf" }),
        expect.objectContaining({ name: "recipient.pem" }),
        "report_encrypted.pqc",
        expect.any(AbortSignal)
      )
    );
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ filename: "report_encrypted.pqc" }));
    expect(await screen.findByText(/saved report_encrypted\.pqc/i)).toBeVisible();
    expect(screen.getByText("New file format version").nextElementSibling).toHaveTextContent("4");
  });

  it("reports a browser download failure separately from a service failure", async () => {
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const encrypt = vi.fn().mockResolvedValue({
      filename: "report_encrypted.pqc",
      blob: new Blob(["ciphertext"])
    });
    const save = vi.fn(() => {
      throw new TypeError("browser download failed");
    });
    const user = userEvent.setup();

    render(<EncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={save} />);
    await prepareEncryption(user);
    await user.click(screen.getByRole("button", { name: "Encrypt file" }));

    expect(
      await screen.findByText("The file was encrypted, but the download could not start. Try encrypting it again.")
    ).toBeVisible();
    expect(screen.queryByText(/could not reach the local service/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/saved report_encrypted\.pqc/i)).not.toBeInTheDocument();
  });

  it("keeps encryption disabled with a textual reason when the plaintext is oversized", async () => {
    const health = { ...READY_HEALTH, maxFileBytes: 3 };
    const encrypt = vi.fn();
    const user = userEvent.setup();

    render(<EncryptWorkflow encrypt={encrypt} health={health} />);
    await user.upload(screen.getByLabelText("File to encrypt"), new File(["four"], "report.pdf"));

    expect(screen.getByRole("button", { name: "Encrypt file" })).toBeDisabled();
    expect(screen.getByText(/exceeds the 3 byte limit/i)).toBeVisible();
    expect(encrypt).not.toHaveBeenCalled();
  });

  it("keeps encryption disabled when inspection finds a private key", async () => {
    const inspect = vi.fn().mockResolvedValue({
      ok: true,
      keyInfo: {
        kem: READY_HEALTH.kem,
        key_type: "private"
      },
      display: {
        "Key Type": "Encrypted private key",
        Algorithm: READY_HEALTH.kem
      }
    });
    const user = userEvent.setup();

    render(<EncryptWorkflow health={READY_HEALTH} inspect={inspect} />);
    await user.upload(screen.getByLabelText("File to encrypt"), new File(["report"], "report.pdf"));
    await user.upload(screen.getByLabelText("Recipient public key"), new File(["PEM"], "recipient.pem"));

    expect(await screen.findByText(/a public key is required/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Encrypt file" })).toBeDisabled();
  });

  it("does not submit a second encryption request while one is in progress", async () => {
    let resolveEncryption: (value: { filename: string; blob: Blob }) => void;
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const encrypt = vi.fn(
      (_file: File, _publicKey: File, _outputFilename: string, _signal?: AbortSignal) =>
        new Promise<{ filename: string; blob: Blob }>((resolve) => {
          resolveEncryption = resolve;
        })
    );
    const user = userEvent.setup();

    render(<EncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />);
    await user.upload(screen.getByLabelText("File to encrypt"), new File(["report"], "report.pdf"));
    await user.upload(screen.getByLabelText("Recipient public key"), new File(["PEM"], "recipient.pem"));
    await screen.findByText("Compatible public key");

    await user.click(screen.getByRole("button", { name: "Encrypt file" }));
    await user.click(screen.getByRole("button", { name: "Encrypting locally" }));

    expect(encrypt).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText("File to encrypt")).toBeDisabled();
    expect(screen.getByLabelText("Recipient public key")).toBeDisabled();
    expect(screen.getByLabelText("Output filename")).toBeDisabled();
    expect(encrypt.mock.calls[0]?.[3]).toBeInstanceOf(AbortSignal);
    resolveEncryption!({ filename: "report_encrypted.pqc", blob: new Blob(["ciphertext"]) });
    expect(await screen.findByText(/saved report_encrypted\.pqc/i)).toBeVisible();
  });

  it("does not accept a public key from a different hybrid suite", async () => {
    const inspect = vi.fn().mockResolvedValue({
      ok: true,
      keyInfo: { kem: "Kyber768", key_type: "public" },
      display: { "Key Type": "Public", Algorithm: "Kyber768" }
    });
    const user = userEvent.setup();

    render(<EncryptWorkflow health={READY_HEALTH} inspect={inspect} />);
    await user.upload(screen.getByLabelText("File to encrypt"), new File(["report"], "report.pdf"));
    await user.upload(screen.getByLabelText("Recipient public key"), new File(["PEM"], "recipient.pem"));

    expect(await screen.findByText(/encryption requires ML-KEM-768\+X25519-v2/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Encrypt file" })).toBeDisabled();
  });

  it("aborts an in-flight encryption request on unmount", async () => {
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const encrypt = vi.fn(
      (_file: File, _publicKey: File, _outputFilename: string, _signal?: AbortSignal) =>
        new Promise<{ filename: string; blob: Blob }>(() => undefined)
    );
    const user = userEvent.setup();
    const { unmount } = render(
      <EncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />
    );

    await prepareEncryption(user);
    await user.click(screen.getByRole("button", { name: "Encrypt file" }));
    await waitFor(() => expect(encrypt).toHaveBeenCalledTimes(1));
    const signal = encrypt.mock.calls[0]?.[3] as AbortSignal;

    unmount();

    expect(signal.aborted).toBe(true);
  });

  it("preserves backend guidance and distinguishes network failure", async () => {
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const user = userEvent.setup();
    const backendFailure = vi.fn().mockRejectedValue(
      new ApiError(503, "backend_unavailable", "Post-quantum backend is not ready.")
    );
    const { unmount } = render(
      <EncryptWorkflow encrypt={backendFailure} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />
    );

    await prepareEncryption(user);
    await user.click(screen.getByRole("button", { name: "Encrypt file" }));
    expect(await screen.findByText("Post-quantum backend is not ready.")).toBeVisible();

    unmount();
    const networkFailure = vi.fn().mockRejectedValue(new TypeError("fetch failed: private socket detail"));
    render(<EncryptWorkflow encrypt={networkFailure} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />);
    await prepareEncryption(user);
    await user.click(screen.getByRole("button", { name: "Encrypt file" }));

    expect(await screen.findByText("Could not reach the local service. Check that it is running and try again.")).toBeVisible();
    expect(screen.queryByText(/private socket detail/i)).not.toBeInTheDocument();
  });

  it("preserves safe recipient-key guidance from the local API", async () => {
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const encrypt = vi.fn().mockRejectedValue(
      new ApiError(
        400,
        "legacy_public_key",
        "Generate a new ML-KEM-768+X25519-v2 public key for encryption."
      )
    );
    const user = userEvent.setup();

    render(<EncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />);
    await prepareEncryption(user);
    await user.click(screen.getByRole("button", { name: "Encrypt file" }));

    expect(
      await screen.findByText("Generate a new ML-KEM-768+X25519-v2 public key for encryption.")
    ).toBeVisible();
  });

  it("does not render an AbortError as an encryption failure", async () => {
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const aborted = new Error("request aborted");
    aborted.name = "AbortError";
    const encrypt = vi.fn().mockRejectedValue(aborted);
    const user = userEvent.setup();

    render(<EncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />);
    await prepareEncryption(user);
    await user.click(screen.getByRole("button", { name: "Encrypt file" }));

    await waitFor(() => expect(screen.getByRole("button", { name: "Encrypt file" })).toBeEnabled());
    expect(screen.queryByText("Encryption failed")).not.toBeInTheDocument();
  });
});
