import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type ChangedPrivateKey } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { ChangeKeyPasswordWorkflow } from "./ChangeKeyPasswordWorkflow";

const currentPassword = "correct horse battery staple";
const newPassword = "different strong passphrase for key";
const updated: ChangedPrivateKey = {
  ok: true, privatePem: "ENCRYPTED UPDATED KEY", privateFilename: "recipient_updated.pem",
  kem: READY_HEALTH.kem, publicKeyFingerprint: `QE1-SHA3-256:${"a".repeat(64)}`
};
const inspectPrivate = () => vi.fn().mockResolvedValue({
  ok: true, keyInfo: { key_type: "private", kem: READY_HEALTH.kem, private_key_encrypted: true }, display: {}
});

async function prepare(user: ReturnType<typeof userEvent.setup>, nextPassword = newPassword) {
  await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["encrypted PEM"], "private.pem"));
  await screen.findByText("Supported encrypted private key");
  await user.type(screen.getByLabelText("Current password", { exact: true }), currentPassword);
  await user.type(screen.getByLabelText("New password", { exact: true }), nextPassword);
  await user.type(screen.getByLabelText("Confirm new password", { exact: true }), nextPassword);
}

describe("ChangeKeyPasswordWorkflow", () => {
  it("requires advertised support, but does not require a native PQC backend", async () => {
    const { rerender } = render(<ChangeKeyPasswordWorkflow health={{ ...READY_HEALTH, supportsKeyPasswordChange: undefined }} />);
    expect(screen.getByText(/restart an updated local service/i)).toBeVisible();
    expect(screen.queryByLabelText("Current password")).not.toBeInTheDocument();
    rerender(<ChangeKeyPasswordWorkflow health={{ ...READY_HEALTH, backendReady: false }} inspect={inspectPrivate()} />);
    await prepare(userEvent.setup());
    expect(screen.getByRole("button", { name: "Change key password" })).toBeEnabled();
  });

  it.each([
    { key_type: "public", kem: READY_HEALTH.kem },
    { key_type: "private", kem: READY_HEALTH.kem, private_key_encrypted: false }
  ])("rejects a key that is not encrypted private material (%#)", async (keyInfo) => {
    const user = userEvent.setup();
    const change = vi.fn();
    render(<ChangeKeyPasswordWorkflow health={READY_HEALTH} inspect={vi.fn().mockResolvedValue({ ok: true, keyInfo, display: {} })} change={change} />);
    await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["key"], "key.pem"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a supported encrypted private key.");
    expect(screen.getByRole("button", { name: "Change key password" })).toBeDisabled();
    expect(change).not.toHaveBeenCalled();
  });

  it("rejects oversized key files before inspection", async () => {
    const user = userEvent.setup();
    const inspect = inspectPrivate();
    render(<ChangeKeyPasswordWorkflow health={{ ...READY_HEALTH, maxPemBytes: 2 }} inspect={inspect} />);
    await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["too large"], "key.pem"));
    expect(screen.getByRole("alert")).toHaveTextContent("exceeds");
    expect(inspect).not.toHaveBeenCalled();
  });

  it.each(["short", currentPassword, "passwordpassword"])("rejects weak or unchanged new passwords (%#)", async (password) => {
    render(<ChangeKeyPasswordWorkflow health={READY_HEALTH} inspect={inspectPrivate()} />);
    await prepare(userEvent.setup(), password);
    expect(screen.getByRole("button", { name: "Change key password" })).toBeDisabled();
  });

  it("requires confirmation and clears entered credentials when selecting another key", async () => {
    const user = userEvent.setup();
    render(<ChangeKeyPasswordWorkflow health={READY_HEALTH} inspect={inspectPrivate()} />);
    await prepare(user);
    await user.type(screen.getByLabelText("Confirm new password", { exact: true }), "mismatch");
    expect(screen.getByRole("button", { name: "Change key password" })).toBeDisabled();
    await user.upload(screen.getByLabelText("Private key", { exact: true }), new File(["different"], "next.pem"));
    expect(screen.getByLabelText("Current password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("New password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Confirm new password", { exact: true })).toHaveValue("");
  });

  it("clears credentials during the request, retains an explicit download, and supports save retry", async () => {
    const user = userEvent.setup();
    let resolve!: (key: ChangedPrivateKey) => void;
    const change = vi.fn().mockReturnValue(new Promise<ChangedPrivateKey>((accept) => { resolve = accept; }));
    const save = vi.fn().mockImplementationOnce(() => { throw new Error("private browser detail"); });
    const onSensitiveResultChange = vi.fn();
    render(<ChangeKeyPasswordWorkflow health={READY_HEALTH} inspect={inspectPrivate()} change={change} save={save} onSensitiveResultChange={onSensitiveResultChange} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Change key password" }));
    expect(screen.getByLabelText("Current password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("New password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Confirm new password", { exact: true })).toHaveValue("");
    expect(screen.getByRole("button", { name: "Changing key password" })).toBeDisabled();
    expect(change).toHaveBeenCalledWith(expect.any(File), currentPassword, newPassword, expect.any(AbortSignal));
    await act(async () => resolve(updated));
    expect(await screen.findByText("Private key password changed")).toBeVisible();
    expect(screen.getByText(updated.publicKeyFingerprint)).toBeVisible();
    expect(save).not.toHaveBeenCalled();
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(true);
    await user.click(screen.getByRole("button", { name: "Download updated private key" }));
    expect(screen.getByRole("alert")).toHaveTextContent("The download could not start");
    await user.click(screen.getByRole("button", { name: "Download updated private key" }));
    expect(save).toHaveBeenCalledTimes(2);
    expect(change).toHaveBeenCalledTimes(1);
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(true);
    expect(screen.getByText("Download started. The browser controls whether it finishes.")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Clear updated key" }));
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(false);
    expect(screen.queryByRole("button", { name: "Download updated private key" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Private key", { exact: true })).toBeEnabled();
  });

  it.each(["reject", "throw"])("clears passwords and displays a safe error on operation %s", async (mode) => {
    const user = userEvent.setup();
    const error = new ApiError(500, "password_change_failed", "raw private backend details");
    const change = mode === "throw" ? vi.fn(() => { throw error; }) : vi.fn().mockRejectedValue(error);
    render(<ChangeKeyPasswordWorkflow health={READY_HEALTH} inspect={inspectPrivate()} change={change} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Change key password" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not change the key password");
    expect(screen.getByRole("alert")).not.toHaveTextContent("raw private");
    expect(screen.getByLabelText("Current password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("New password", { exact: true })).toHaveValue("");
    expect(screen.getByLabelText("Private key", { exact: true })).toBeEnabled();
  });

  it("aborts when leaving and suppresses a late key result", async () => {
    const user = userEvent.setup();
    let resolve!: (key: ChangedPrivateKey) => void;
    const change = vi.fn().mockReturnValue(new Promise<ChangedPrivateKey>((accept) => { resolve = accept; }));
    const onSensitiveResultChange = vi.fn();
    const { unmount } = render(<ChangeKeyPasswordWorkflow health={READY_HEALTH} inspect={inspectPrivate()} change={change} onSensitiveResultChange={onSensitiveResultChange} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Change key password" }));
    unmount();
    expect(change.mock.calls[0][3].aborted).toBe(true);
    await act(async () => resolve(updated));
    expect(onSensitiveResultChange).toHaveBeenLastCalledWith(false);
    expect(onSensitiveResultChange).not.toHaveBeenCalledWith(true);
  });
});
