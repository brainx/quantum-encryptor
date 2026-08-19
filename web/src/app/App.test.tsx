import { StrictMode } from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { READY_HEALTH } from "../test/fixtures";
import App from "./App";

const client = vi.hoisted(() => ({
  fetchHealth: vi.fn(),
  generateKeys: vi.fn()
}));

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    fetchHealth: client.fetchHealth,
    generateKeys: client.generateKeys
  };
});

async function openGeneratedKeys(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByRole("heading", { name: "Encrypt a file" });
  await user.click(screen.getByRole("button", { name: "Generate keys" }));
  await screen.findByRole("heading", { name: "Generate keys" });
  await user.type(screen.getByLabelText("Private key password"), "correct horse battery staple");
  await user.type(screen.getByLabelText("Confirm private key password"), "correct horse battery staple");
  await user.click(screen.getByRole("button", { name: "Generate key pair" }));
  await screen.findByRole("button", { name: "Download public key" });
}

beforeEach(() => {
  client.fetchHealth.mockReset();
  client.fetchHealth.mockResolvedValue(READY_HEALTH);
  client.generateKeys.mockReset();
  client.generateKeys.mockResolvedValue({
    ok: true,
    kem: READY_HEALTH.kem,
    publicPem: "PUBLIC-PEM",
    privatePem: "ENCRYPTED-PRIVATE-PEM",
    publicFilename: "recipient-public.pem",
    privateFilename: "recipient-private.pem"
  });
});

describe("App", () => {
  it("starts on file encryption and switches to key inspection", async () => {
    const user = userEvent.setup();

    render(<App />);

    expect(await screen.findByRole("heading", { name: "Encrypt a file" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Inspect key" }));

    expect(await screen.findByRole("heading", { name: "Inspect a key" })).toBeVisible();
  });

  it("coalesces the initial health request in StrictMode while workflows stay unmounted", async () => {
    let resolveHealth: (health: typeof READY_HEALTH) => void = () => undefined;
    const pendingHealth = new Promise<typeof READY_HEALTH>((resolve) => {
      resolveHealth = resolve;
    });
    client.fetchHealth.mockReturnValue(pendingHealth);

    render(
      <StrictMode>
        <App />
      </StrictMode>
    );

    expect(client.fetchHealth).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status")).toHaveTextContent("Loading local engine status.");
    expect(screen.queryByRole("heading", { name: "Encrypt a file" })).not.toBeInTheDocument();

    resolveHealth(READY_HEALTH);

    expect(await screen.findByRole("heading", { name: "Encrypt a file" })).toBeVisible();
  });

  it("retries a failed health request with a fresh request and safe recovery", async () => {
    client.fetchHealth.mockRejectedValueOnce(new Error("raw backend connection details"));
    client.fetchHealth.mockResolvedValueOnce(READY_HEALTH);
    const user = userEvent.setup();

    render(<App />);

    expect(
      await screen.findByText("The local engine status could not be loaded. Restart the app and try again.")
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Retry" })).toBeEnabled();
    expect(screen.queryByText("raw backend connection details")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry" }));

    expect(client.fetchHealth).toHaveBeenCalledTimes(2);
    expect(await screen.findByRole("heading", { name: "Encrypt a file" })).toBeVisible();
  });

  it("cancels page leave only while generated keys remain", async () => {
    const user = userEvent.setup();

    render(<App />);
    await screen.findByRole("heading", { name: "Encrypt a file" });
    const initialEvent = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(initialEvent)).toBe(true);
    expect(initialEvent.defaultPrevented).toBe(false);

    await openGeneratedKeys(user);
    const activeEvent = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(activeEvent)).toBe(false);
    expect(activeEvent.defaultPrevented).toBe(true);

    await user.click(screen.getByRole("button", { name: "Clear generated keys" }));
    const clearedEvent = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(clearedEvent)).toBe(true);
    expect(clearedEvent.defaultPrevented).toBe(false);
  });

  it("allows page leave while key generation is pending or failed", async () => {
    let rejectGeneration: (reason?: unknown) => void = () => undefined;
    client.generateKeys.mockReturnValue(
      new Promise((_resolve, reject) => {
        rejectGeneration = reject;
      })
    );
    const user = userEvent.setup();

    render(<App />);
    await screen.findByRole("heading", { name: "Encrypt a file" });
    await user.click(screen.getByRole("button", { name: "Generate keys" }));
    await screen.findByRole("heading", { name: "Generate keys" });
    await user.type(screen.getByLabelText("Private key password"), "correct horse battery staple");
    await user.type(screen.getByLabelText("Confirm private key password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Generate key pair" }));
    expect(await screen.findByRole("button", { name: "Generating key pair" })).toBeDisabled();

    const pendingEvent = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(pendingEvent)).toBe(true);
    expect(pendingEvent.defaultPrevented).toBe(false);

    await act(async () => {
      rejectGeneration(new Error("raw backend generation details"));
    });
    expect(
      await screen.findByText("Could not generate keys. Check the password requirements and try again.")
    ).toBeVisible();

    const failedEvent = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(failedEvent)).toBe(true);
    expect(failedEvent.defaultPrevented).toBe(false);
  });

  it("restores page leave when the app unmounts", async () => {
    const user = userEvent.setup();
    const { unmount } = render(<App />);

    await openGeneratedKeys(user);
    const activeEvent = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(activeEvent)).toBe(false);

    unmount();

    const unmountedEvent = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(unmountedEvent)).toBe(true);
    expect(unmountedEvent.defaultPrevented).toBe(false);
  });

  it("keeps generated keys active when leaving is cancelled", async () => {
    const user = userEvent.setup();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);

    render(<App />);
    await openGeneratedKeys(user);
    await user.click(screen.getByRole("button", { name: "Inspect key" }));

    expect(confirm).toHaveBeenCalledWith("Generated keys are still available. Leave this workflow and clear them?");
    expect(screen.getByRole("heading", { name: "Generate keys" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Download public key" })).toBeVisible();
  });

  it("clears generated-key state before leaving after confirmation", async () => {
    const user = userEvent.setup();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);

    render(<App />);
    await openGeneratedKeys(user);
    await user.click(screen.getByRole("button", { name: "Inspect key" }));

    expect(confirm).toHaveBeenCalledWith("Generated keys are still available. Leave this workflow and clear them?");
    expect(await screen.findByRole("heading", { name: "Inspect a key" })).toBeVisible();

    const navigatedEvent = new Event("beforeunload", { cancelable: true });
    expect(window.dispatchEvent(navigatedEvent)).toBe(true);
    expect(navigatedEvent.defaultPrevented).toBe(false);

    await user.click(screen.getByRole("button", { name: "Generate keys" }));
    await screen.findByRole("heading", { name: "Generate keys" });
    await user.click(screen.getByRole("button", { name: "Encrypt" }));

    await waitFor(() => expect(screen.getByRole("heading", { name: "Encrypt a file" })).toBeVisible());
    expect(confirm).toHaveBeenCalledTimes(1);
  });
});
