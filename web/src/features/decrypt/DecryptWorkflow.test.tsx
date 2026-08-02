import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { DecryptWorkflow } from "./DecryptWorkflow";

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
};

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function privateKeyInspection() {
  return {
    ok: true,
    keyInfo: {
      kem: READY_HEALTH.kem,
      key_type: "private" as const,
      private_key_encrypted: true,
      private_key_format_version: 3,
      private_key_kdf: "scrypt"
    },
    display: {
      "Key Type": "Encrypted private key",
      "Key Format": "3",
      "Key KDF": "scrypt",
      Algorithm: READY_HEALTH.kem
    }
  };
}

describe("DecryptWorkflow", () => {
  it("decrypts with an inspected private key, saves the suggested filename, and clears the password", async () => {
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const decrypt = vi.fn().mockResolvedValue({
      filename: "report",
      blob: new Blob(["plaintext"])
    });
    const save = vi.fn();
    const user = userEvent.setup();

    render(<DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={save} />);

    await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
    expect(await screen.findByText("Supported encrypted private key; match not yet verified")).toBeVisible();

    const password = screen.getByLabelText("Private key password");
    await user.type(password, "correct horse battery staple");
    expect(screen.getByLabelText("Output filename")).toHaveValue("report");

    await user.click(screen.getByRole("button", { name: "Decrypt file" }));

    await waitFor(() =>
      expect(decrypt).toHaveBeenCalledWith(
        expect.objectContaining({ name: "report_encrypted.pqc" }),
        expect.objectContaining({ name: "recipient_private.pem" }),
        "correct horse battery staple",
        "report",
        expect.any(AbortSignal)
      )
    );
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ filename: "report" }));
    expect(password).toHaveValue("");
  });

  it("reports a browser download failure separately and still clears the password", async () => {
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const decrypt = vi.fn().mockResolvedValue({ filename: "report", blob: new Blob(["plaintext"]) });
    const save = vi.fn(() => {
      throw new TypeError("browser download failed");
    });
    const user = userEvent.setup();

    render(<DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={save} />);
    await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
    await screen.findByText("Supported encrypted private key; match not yet verified");
    const password = screen.getByLabelText("Private key password");
    await user.type(password, "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Decrypt file" }));

    expect(
      await screen.findByText("The file was decrypted, but the download could not start. Try decrypting it again.")
    ).toBeVisible();
    expect(screen.queryByText(/could not reach the local service/i)).not.toBeInTheDocument();
    expect(password).toHaveValue("");
  });

  it("uses a safe authentication failure message without singling out a secret", async () => {
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const decrypt = vi.fn().mockRejectedValue(
      new ApiError(
        400,
        "decryption_failed",
        "Decryption failed. Check the private key, password, and encrypted file integrity."
      )
    );
    const user = userEvent.setup();

    render(<DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />);

    await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
    await screen.findByText("Supported encrypted private key; match not yet verified");
    const password = screen.getByLabelText("Private key password");
    await user.type(password, "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Decrypt file" }));

    expect(
      await screen.findByText("The file could not be authenticated. Check the encrypted file, private key, and password.")
    ).toBeVisible();
    expect(screen.queryByText(/decryption failed\. check/i)).not.toBeInTheDocument();
    expect(password).toHaveValue("correct horse battery staple");
  });

  it("locks every causal input while a decryption request is in flight", async () => {
    const inspection = vi.fn().mockResolvedValue(privateKeyInspection());
    const request = deferred<{ filename: string; blob: Blob }>();
    const decrypt = vi.fn().mockReturnValue(request.promise);
    const user = userEvent.setup();

    render(<DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspection} save={vi.fn()} />);

    await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
    await screen.findByText("Supported encrypted private key; match not yet verified");
    const password = screen.getByLabelText("Private key password");
    await user.type(password, "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Decrypt file" }));
    await waitFor(() => expect(decrypt).toHaveBeenCalledTimes(1));

    expect(screen.getByLabelText("Encrypted file")).toBeDisabled();
    expect(screen.getByLabelText("Private key")).toBeDisabled();
    expect(password).toBeDisabled();
    expect(screen.getByLabelText("Output filename")).toBeDisabled();
    await user.type(password, "x");
    expect(password).toHaveValue("correct horse battery staple");

    request.resolve({ filename: "report", blob: new Blob(["plaintext"]) });
  });

  it("clears a completed decryption outcome when the password changes while idle", async () => {
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const decrypt = vi.fn().mockResolvedValue({ filename: "report", blob: new Blob(["plaintext"]) });
    const user = userEvent.setup();

    render(<DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />);

    await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
    await screen.findByText("Supported encrypted private key; match not yet verified");
    const password = screen.getByLabelText("Private key password");
    await user.type(password, "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Decrypt file" }));
    expect(await screen.findByText("Saved report.")).toBeVisible();

    await user.type(password, "new");

    expect(screen.queryByText("Saved report.")).not.toBeInTheDocument();
    expect(screen.queryByText("File decrypted")).not.toBeInTheDocument();
  });

  it("hides inspection failure details while keeping decryption unavailable", async () => {
    const inspect = vi.fn().mockRejectedValue(new Error("private parser detail: /secret/path/key.pem"));
    const user = userEvent.setup();

    render(<DecryptWorkflow health={READY_HEALTH} inspect={inspect} />);

    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));

    expect(await screen.findByText("The private key could not be inspected.")).toBeVisible();
    expect(screen.queryByText(/private parser detail/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decrypt file" })).toBeDisabled();
  });

  it("rejects oversized encrypted files locally before decryption", async () => {
    const health = { ...READY_HEALTH, maxEncryptedFileBytes: 3 };
    const decrypt = vi.fn();
    const user = userEvent.setup();

    render(<DecryptWorkflow decrypt={decrypt} health={health} inspect={vi.fn()} />);

    await user.upload(screen.getByLabelText("Encrypted file"), new File(["four"], "report_encrypted.pqc"));

    expect(screen.getByText("This encrypted file exceeds the 3 byte limit.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Decrypt file" })).toBeDisabled();
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("accepts a legacy private key classification without rejecting its suite before authentication", async () => {
    const inspect = vi.fn().mockResolvedValue({
      ...privateKeyInspection(),
      keyInfo: {
        ...privateKeyInspection().keyInfo,
        kem: "ML-KEM-768+X25519"
      }
    });
    const decrypt = vi.fn().mockResolvedValue({ filename: "report", blob: new Blob(["plaintext"]) });
    const user = userEvent.setup();

    render(<DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />);

    await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
    await screen.findByText("Supported encrypted private key; match not yet verified");
    await user.type(screen.getByLabelText("Private key password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Decrypt file" }));

    await waitFor(() => expect(decrypt).toHaveBeenCalledTimes(1));
  });

  it("does not claim a selected container version or pre-authentication key match", async () => {
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const user = userEvent.setup();

    render(<DecryptWorkflow health={READY_HEALTH} inspect={inspect} />);
    await user.upload(screen.getByLabelText("Encrypted file"), new File(["legacy"], "archive.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "archive-private.pem"));

    expect(await screen.findByText("Supported encrypted private key; match not yet verified")).toBeVisible();
    expect(screen.queryByText("Compatible private key")).not.toBeInTheDocument();
    expect(screen.queryByText("File format version")).not.toBeInTheDocument();
  });

  it("aborts an in-flight decryption request on unmount", async () => {
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const decrypt = vi.fn(
      (_file: File, _privateKey: File, _password: string, _outputFilename: string, _signal?: AbortSignal) =>
        new Promise<{ filename: string; blob: Blob }>(() => undefined)
    );
    const user = userEvent.setup();
    const { unmount } = render(
      <DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />
    );

    await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
    await screen.findByText("Supported encrypted private key; match not yet verified");
    await user.type(screen.getByLabelText("Private key password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Decrypt file" }));
    await waitFor(() => expect(decrypt).toHaveBeenCalledTimes(1));
    const signal = decrypt.mock.calls[0]?.[4] as AbortSignal;

    unmount();

    expect(signal.aborted).toBe(true);
  });

  it("preserves backend and invalid-key guidance while distinguishing network failure", async () => {
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const user = userEvent.setup();
    const renderFailure = async (failure: unknown) => {
      const decrypt = vi.fn().mockRejectedValue(failure);
      const rendered = render(
        <DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />
      );
      await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
      await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
      await screen.findByText("Supported encrypted private key; match not yet verified");
      await user.type(screen.getByLabelText("Private key password"), "correct horse battery staple");
      await user.click(screen.getByRole("button", { name: "Decrypt file" }));
      return rendered;
    };

    let rendered = await renderFailure(new ApiError(503, "backend_unavailable", "Post-quantum backend is not ready."));
    expect(await screen.findByText("Post-quantum backend is not ready.")).toBeVisible();
    rendered.unmount();

    rendered = await renderFailure(
      new ApiError(400, "invalid_private_key", "Upload a supported encrypted PQC private key PEM file.")
    );
    expect(await screen.findByText("Upload a supported encrypted PQC private key PEM file.")).toBeVisible();
    rendered.unmount();

    await renderFailure(new TypeError("fetch failed: private socket detail"));
    expect(await screen.findByText("Could not reach the local service. Check that it is running and try again.")).toBeVisible();
    expect(screen.queryByText(/private socket detail/i)).not.toBeInTheDocument();
  });

  it("does not render an AbortError as a decryption failure", async () => {
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const aborted = new Error("request aborted");
    aborted.name = "AbortError";
    const decrypt = vi.fn().mockRejectedValue(aborted);
    const user = userEvent.setup();

    render(<DecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={vi.fn()} />);
    await user.upload(screen.getByLabelText("Encrypted file"), new File(["ciphertext"], "report_encrypted.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient_private.pem"));
    await screen.findByText("Supported encrypted private key; match not yet verified");
    await user.type(screen.getByLabelText("Private key password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Decrypt file" }));

    await waitFor(() => expect(screen.getByRole("button", { name: "Decrypt file" })).toBeEnabled());
    expect(screen.queryByText("Decryption failed")).not.toBeInTheDocument();
  });
});
