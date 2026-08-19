import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type GeneratedKeys } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { GenerateKeysWorkflow } from "./GenerateKeysWorkflow";

function generatedKeys(overrides: Partial<GeneratedKeys> = {}): GeneratedKeys {
  return {
    ok: true,
    kem: "ML-KEM-768+X25519-v2",
    publicPem: "PUBLIC-PEM",
    privatePem: "-----BEGIN PQC PRIVATE KEY-----\nPQC-Key-Format: 3\nENCRYPTED-PRIVATE-PEM\n-----END PQC PRIVATE KEY-----",
    publicFilename: "recipient-public.pem",
    privateFilename: "recipient-private.pem",
    ...overrides
  };
}

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

async function enterValidPasswords(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Private key password"), "correct horse battery staple");
  await user.type(screen.getByLabelText("Confirm private key password"), "correct horse battery staple");
}

describe("GenerateKeysWorkflow", () => {
  it("keeps generation disabled for a server-blocked common password", async () => {
    const user = userEvent.setup();

    render(<GenerateKeysWorkflow health={READY_HEALTH} />);
    await user.type(screen.getByLabelText("Private key password"), "password12345678");
    await user.type(screen.getByLabelText("Confirm private key password"), "password12345678");

    expect(screen.getByText("Not a common password").closest("li")).not.toHaveClass("password-policy-met");
    expect(screen.getByRole("button", { name: "Generate key pair" })).toBeDisabled();
  });

  it("keeps generated key material in memory until the user explicitly clears it", async () => {
    const generate = vi.fn().mockResolvedValue(generatedKeys());
    const onSensitiveResultChange = vi.fn();
    const user = userEvent.setup();

    render(
      <GenerateKeysWorkflow
        generate={generate}
        health={READY_HEALTH}
        onSensitiveResultChange={onSensitiveResultChange}
      />
    );

    const generateButton = screen.getByRole("button", { name: "Generate key pair" });
    expect(generateButton).toBeDisabled();

    await enterValidPasswords(user);
    expect(generateButton).toBeEnabled();

    await user.click(generateButton);

    await waitFor(() =>
      expect(generate).toHaveBeenCalledWith("correct horse battery staple", expect.any(AbortSignal))
    );
    expect(screen.queryByLabelText("Private key password")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Confirm private key password")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download public key" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Download encrypted private key" })).toBeVisible();
    expect(
      screen.getByText(
        "Save both files now. The app keeps this generated result in this tab, and you may lose it if you clear it, reload, or leave the page. The public key is safe to share; keep the encrypted private key and password secure."
      )
    ).toBeVisible();
    expect(screen.queryByText("PUBLIC-PEM")).not.toBeInTheDocument();
    expect(screen.queryByText("ENCRYPTED-PRIVATE-PEM")).not.toBeInTheDocument();
    expect(onSensitiveResultChange).toHaveBeenCalledWith(true);
    expect(screen.getByText("Private key format version").nextElementSibling).toHaveTextContent("3");

    await user.click(screen.getByRole("button", { name: "Clear generated keys" }));

    expect(screen.queryByRole("button", { name: "Download public key" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Download encrypted private key" })).not.toBeInTheDocument();
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(false);
  });

  it("requires clearing generated keys before another key pair can be requested", async () => {
    const secondRequest = new Promise<GeneratedKeys>(() => undefined);
    const generate = vi.fn()
      .mockResolvedValueOnce(generatedKeys())
      .mockReturnValueOnce(secondRequest);
    const onSensitiveResultChange = vi.fn();
    const user = userEvent.setup();

    render(
      <GenerateKeysWorkflow
        generate={generate}
        health={READY_HEALTH}
        onSensitiveResultChange={onSensitiveResultChange}
      />
    );

    await enterValidPasswords(user);
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));
    await waitFor(() => expect(generate).toHaveBeenCalledTimes(1));
    expect(screen.getByRole("button", { name: "Download public key" })).toBeVisible();
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(true);

    expect(screen.queryByLabelText("Private key password")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Generate key pair" })).not.toBeInTheDocument();
    expect(generate).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Download encrypted private key" })).toBeVisible();
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(true);

    await user.click(screen.getByRole("button", { name: "Clear generated keys" }));

    expect(screen.getByLabelText("Private key password")).toBeVisible();
    expect(screen.getByRole("button", { name: "Generate key pair" })).toBeDisabled();
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(false);
  });

  it("notifies the shell to clear sensitive result state when unmounted", () => {
    const onSensitiveResultChange = vi.fn();
    const { unmount } = render(
      <GenerateKeysWorkflow health={READY_HEALTH} onSensitiveResultChange={onSensitiveResultChange} />
    );

    unmount();

    expect(onSensitiveResultChange).toHaveBeenCalledWith(false);
  });

  it("does not reassert sensitive state when an in-flight request resolves after unmount", async () => {
    let resolveGeneration: (value: ReturnType<typeof generatedKeys>) => void;
    const generate = vi.fn(
      (_password: string, _signal?: AbortSignal) =>
        new Promise<ReturnType<typeof generatedKeys>>((resolve) => {
          resolveGeneration = resolve;
        })
    );
    const onSensitiveResultChange = vi.fn();
    const user = userEvent.setup();
    const { unmount } = render(
      <GenerateKeysWorkflow
        generate={generate}
        health={READY_HEALTH}
        onSensitiveResultChange={onSensitiveResultChange}
      />
    );

    await enterValidPasswords(user);
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));
    await waitFor(() => expect(generate).toHaveBeenCalledTimes(1));
    const signal = generate.mock.calls[0]?.[1] as AbortSignal;

    unmount();
    expect(signal.aborted).toBe(true);
    resolveGeneration!(generatedKeys());
    await Promise.resolve();

    expect(onSensitiveResultChange).not.toHaveBeenCalledWith(true);
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(false);
  });

  it("locks password controls while generation is in flight", async () => {
    const request = deferred<GeneratedKeys>();
    const generate = vi.fn().mockReturnValue(request.promise);
    const user = userEvent.setup();

    render(<GenerateKeysWorkflow generate={generate} health={READY_HEALTH} />);
    await enterValidPasswords(user);
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));
    await waitFor(() => expect(generate).toHaveBeenCalledTimes(1));

    expect(screen.getByLabelText("Private key password")).toBeDisabled();
    expect(screen.getByLabelText("Confirm private key password")).toBeDisabled();
    for (const button of screen.getAllByRole("button", { name: "Show password" })) {
      expect(button).toBeDisabled();
    }
    expect(screen.getByRole("button", { name: "Generating key pair" })).toBeDisabled();

    request.resolve(generatedKeys());
    expect(await screen.findByRole("button", { name: "Download public key" })).toBeVisible();
  });

  it("preserves safe backend error categories and distinguishes network failure", async () => {
    const backendFailure = vi.fn().mockRejectedValue(
      new ApiError(503, "backend_unavailable", "Post-quantum backend is not ready.")
    );
    const user = userEvent.setup();
    const { unmount } = render(<GenerateKeysWorkflow generate={backendFailure} health={READY_HEALTH} />);

    await enterValidPasswords(user);
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));
    expect(await screen.findByText("Post-quantum backend is not ready.")).toBeVisible();

    unmount();
    const networkFailure = vi.fn().mockRejectedValue(new TypeError("fetch failed: private socket detail"));
    render(<GenerateKeysWorkflow generate={networkFailure} health={READY_HEALTH} />);
    await enterValidPasswords(user);
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));

    expect(await screen.findByText("Could not reach the local service. Check that it is running and try again.")).toBeVisible();
    expect(screen.queryByText(/private socket detail/i)).not.toBeInTheDocument();
  });

  it("preserves safe server password-policy guidance", async () => {
    const generate = vi.fn().mockRejectedValue(
      new ApiError(400, "weak_password", "Private-key password is too common.")
    );
    const user = userEvent.setup();

    render(<GenerateKeysWorkflow generate={generate} health={READY_HEALTH} />);
    await enterValidPasswords(user);
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));

    expect(await screen.findByText("Private-key password is too common.")).toBeVisible();
  });

  it("does not render an AbortError as a key-generation failure", async () => {
    const aborted = new Error("request aborted");
    aborted.name = "AbortError";
    const generate = vi.fn().mockRejectedValue(aborted);
    const user = userEvent.setup();

    render(<GenerateKeysWorkflow generate={generate} health={READY_HEALTH} />);
    await enterValidPasswords(user);
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));

    await waitFor(() => expect(screen.getByRole("button", { name: "Generate key pair" })).toBeEnabled());
    expect(screen.queryByText("Key generation failed")).not.toBeInTheDocument();
  });

  it("does not announce or expose an unsuccessful generation response", async () => {
    const generate = vi.fn().mockResolvedValue(generatedKeys({ ok: false }));
    const onSensitiveResultChange = vi.fn();
    const user = userEvent.setup();

    render(
      <GenerateKeysWorkflow
        generate={generate}
        health={READY_HEALTH}
        onSensitiveResultChange={onSensitiveResultChange}
      />
    );

    await enterValidPasswords(user);
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));

    expect(await screen.findByText("Could not generate keys. Check the password requirements and try again.")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Download public key" })).not.toBeInTheDocument();
    expect(onSensitiveResultChange).not.toHaveBeenCalledWith(true);
  });
});
