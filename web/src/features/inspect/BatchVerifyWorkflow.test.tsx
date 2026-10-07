import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type DownloadResult, type FileVerification, type KeyInspectResult } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { BatchVerifyWorkflow } from "./BatchVerifyWorkflow";

const password = "private password for this test";
const fingerprint = `QE1-SHA3-256:${"a".repeat(64)}`;
const file = (name = "report.pqc", size = 10) => new File([new Uint8Array(size)], name);
const inspection = (): KeyInspectResult => ({ ok: true, keyInfo: {
  key_type: "private", private_key_encrypted: true, kem: READY_HEALTH.kem
}, display: {} });
const report = (): FileVerification => ({ ok: true, verified: true, formatVersion: 4,
  kem: READY_HEALTH.kem, bytesVerified: 3, publicKeyFingerprint: fingerprint });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}
function readBlob(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}
async function prepare(user: ReturnType<typeof userEvent.setup>, files = [file()]) {
  await user.upload(screen.getByLabelText("Files to verify"), files);
  await user.upload(screen.getByLabelText("Private key"), new File(["private PEM bytes"], "private.pem"));
  await screen.findByText("Supported encrypted private key; each file is authenticated separately");
  await user.type(screen.getByLabelText("Private key password"), password);
}

describe("BatchVerifyWorkflow", () => {
  it("adds, removes, and reselects files with native multiple selection and drop", async () => {
    const user = userEvent.setup();
    render(<BatchVerifyWorkflow health={READY_HEALTH} />);
    const input = screen.getByLabelText("Files to verify");
    const first = file("first.pqc");
    expect(input).toHaveAttribute("multiple");
    await user.upload(input, first);
    expect(input).toHaveValue("");
    fireEvent.drop(input.closest("label")!, { dataTransfer: { files: [file("second.pqc")] } });
    expect(within(screen.getByRole("list", { name: "Selected files" })).getAllByRole("listitem")).toHaveLength(2);
    await user.click(screen.getByRole("button", { name: "Remove first.pqc" }));
    await user.upload(input, first);
    expect(screen.getByRole("button", { name: "Remove first.pqc" })).toBeVisible();
  });

  it.each([
    [Array.from({ length: 26 }, () => file("many.pqc", 1)), READY_HEALTH],
    [[file("first.pqc", 3), file("second.pqc", 2)], { ...READY_HEALTH, maxEncryptedFileBytes: 4 }],
    [[file("large.pqc", 5)], { ...READY_HEALTH, maxEncryptedFileBytes: 4 }]
  ])("rejects an oversized selection before queueing (%#)", async (files, health) => {
    const verify = vi.fn();
    render(<BatchVerifyWorkflow health={health} verify={verify} />);
    await userEvent.setup().upload(screen.getByLabelText("Files to verify"), files);
    expect(screen.getByRole("alert")).toHaveTextContent("Files were not added.");
    expect(screen.queryByRole("list", { name: "Selected files" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify batch" })).toBeDisabled();
    expect(verify).not.toHaveBeenCalled();
  });

  it.each([
    { ...READY_HEALTH, supportsFileVerification: undefined },
    { ...READY_HEALTH, capabilities: { ...READY_HEALTH.capabilities, decrypt: { available: false, reason: "Backend unavailable" } } }
  ])("does not offer verification when the service lacks support (%#)", (health) => {
    render(<BatchVerifyWorkflow health={health} />);
    expect(screen.queryByLabelText("Files to verify")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Verify batch" })).not.toBeInTheDocument();
  });

  it.each([
    { ok: true, keyInfo: { key_type: "public", kem: READY_HEALTH.kem, public_key_fingerprint: fingerprint }, display: {} },
    { ok: true, keyInfo: { key_type: "private", kem: READY_HEALTH.kem, private_key_encrypted: false }, display: {} },
    { ok: false, keyInfo: { key_type: "private", kem: READY_HEALTH.kem, private_key_encrypted: true }, display: {} }
  ])("fails closed for an incompatible key (%#)", async (keyResult) => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(keyResult);
    const verify = vi.fn();
    render(<BatchVerifyWorkflow health={READY_HEALTH} inspect={inspect} verify={verify} />);
    await user.upload(screen.getByLabelText("Files to verify"), file());
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "key.pem"));
    await waitFor(() => expect(inspect).toHaveBeenCalled());
    await user.type(screen.getByLabelText("Private key password"), password);
    expect(screen.getByRole("button", { name: "Verify batch" })).toBeDisabled();
    fireEvent.submit(screen.getByRole("button", { name: "Verify batch" }).closest("form")!);
    expect(verify).not.toHaveBeenCalled();
  });

  it("rejects an oversized private key before inspection or verification", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn();
    const verify = vi.fn();
    render(<BatchVerifyWorkflow health={{ ...READY_HEALTH, maxPemBytes: 3 }} inspect={inspect} verify={verify} />);
    await user.upload(screen.getByLabelText("Files to verify"), file());
    await user.upload(screen.getByLabelText("Private key"), new File(["large key"], "private.pem"));
    expect(screen.getByRole("alert")).toHaveTextContent("This key file exceeds");
    expect(screen.getByRole("button", { name: "Verify batch" })).toBeDisabled();
    expect(inspect).not.toHaveBeenCalled();
    expect(verify).not.toHaveBeenCalled();
  });

  it("discards the previous password and stale inspection when the selected key changes", async () => {
    const user = userEvent.setup();
    const first = deferred<KeyInspectResult>();
    const second = deferred<KeyInspectResult>();
    const inspect = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const verify = vi.fn();
    render(<BatchVerifyWorkflow health={READY_HEALTH} inspect={inspect} verify={verify} />);
    await user.upload(screen.getByLabelText("Files to verify"), file());
    await user.upload(screen.getByLabelText("Private key"), new File(["first"], "first.pem"));
    await user.type(screen.getByLabelText("Private key password"), password);
    await user.upload(screen.getByLabelText("Private key"), new File(["second"], "second.pem"));
    expect(screen.getByLabelText("Private key password")).toHaveValue("");
    await act(async () => first.resolve(inspection()));
    await user.type(screen.getByLabelText("Private key password"), password);
    expect(screen.getByRole("button", { name: "Verify batch" })).toBeDisabled();
    await act(async () => second.resolve(inspection()));
    expect(screen.getByRole("button", { name: "Verify batch" })).toBeEnabled();
    expect(verify).not.toHaveBeenCalled();
  });

  it("clears the password immediately, locks the selection, and requires an explicit public report download", async () => {
    const user = userEvent.setup();
    const pending = deferred<FileVerification>();
    const verify = vi.fn().mockReturnValue(pending.promise);
    const save = vi.fn<(result: DownloadResult) => void>();
    const guard = vi.fn();
    render(<BatchVerifyWorkflow health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(inspection())}
      verify={verify} save={save} onPendingResultsChange={guard} />);
    await prepare(user);
    await user.click(screen.getByRole("button", { name: "Verify batch" }));
    expect(screen.getByLabelText("Private key password")).toHaveValue("");
    expect(screen.getByLabelText("Private key password")).toBeDisabled();
    expect(screen.getByLabelText("Files to verify")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Download verification report" })).toBeDisabled();
    expect(guard).toHaveBeenLastCalledWith(true);
    expect(verify).toHaveBeenCalledWith(expect.any(File), expect.any(File), password, expect.any(AbortSignal));
    await act(async () => pending.resolve(report()));
    expect(await screen.findByText("Authenticated", { exact: true })).toBeVisible();
    expect(guard).toHaveBeenLastCalledWith(true);
    expect(save).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Download verification report" }));
    expect(guard).toHaveBeenLastCalledWith(false);
    expect(screen.getByText(/Report download started/)).toBeVisible();
    const output = save.mock.calls[0][0];
    expect(output.filename).toBe("verification-report.json");
    expect(output.blob.type).toBe("application/json");
    const json = await readBlob(output.blob);
    expect(JSON.parse(json).totals).toEqual({ files: 1, authenticated: 1, failed: 0, cancelled: 0 });
    expect(json).toContain(fingerprint);
    expect(json).not.toContain(password);
    expect(json).not.toContain("private PEM bytes");
    await user.click(screen.getByRole("button", { name: "Clear batch" }));
    expect(screen.getByLabelText("Files to verify")).toBeEnabled();
    expect(screen.getByLabelText("Private key password")).toHaveValue("");
    expect(screen.queryByRole("list", { name: "File verification results" })).not.toBeInTheDocument();
  });

  it("shows mixed authentication results and lets report download failures retry without reverifying", async () => {
    const user = userEvent.setup();
    const verify = vi.fn().mockRejectedValueOnce(new ApiError(400, "verification_failed", "internal detail"))
      .mockResolvedValueOnce(report());
    const save = vi.fn().mockImplementationOnce(() => { throw new Error("private download detail"); });
    const guard = vi.fn();
    render(<BatchVerifyWorkflow health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(inspection())}
      verify={verify} save={save} onPendingResultsChange={guard} />);
    await prepare(user, [file("bad.pqc"), file("good.pqc")]);
    await user.click(screen.getByRole("button", { name: "Verify batch" }));
    expect(await screen.findByText(/2 of 2 files processed · 1 authenticated · 1 failed/)).toBeVisible();
    expect(screen.getByText(/The file could not be authenticated/)).toBeVisible();
    const download = screen.getByRole("button", { name: "Download verification report" });
    await user.click(download);
    expect(screen.getByText(/report download could not start/)).toBeVisible();
    expect(screen.queryByText("private download detail")).not.toBeInTheDocument();
    expect(guard).toHaveBeenLastCalledWith(true);
    await user.click(download);
    expect(verify).toHaveBeenCalledTimes(2);
    expect(save).toHaveBeenCalledTimes(2);
    expect(guard).toHaveBeenLastCalledWith(false);
    expect(screen.queryByText(/report download could not start/)).not.toBeInTheDocument();
  });

  it("retains completed reports on cancellation but waits for the active request before export", async () => {
    const user = userEvent.setup();
    const pending = deferred<FileVerification>();
    const verify = vi.fn().mockResolvedValueOnce(report()).mockReturnValueOnce(pending.promise);
    const save = vi.fn();
    render(<BatchVerifyWorkflow health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(inspection())} verify={verify} save={save} />);
    await prepare(user, [file("complete.pqc"), file("active.pqc"), file("queued.pqc")]);
    await user.click(screen.getByRole("button", { name: "Verify batch" }));
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(2));
    await user.click(screen.getByRole("button", { name: "Cancel batch" }));
    expect(screen.getByRole("button", { name: "Clear batch" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Download verification report" })).toBeDisabled();
    expect(verify.mock.calls[1][3].aborted).toBe(true);
    await act(async () => pending.resolve(report()));
    expect(await screen.findByText(/3 of 3 files processed · 1 authenticated · 0 failed · 2 cancelled/)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Download verification report" }));
    expect(save).toHaveBeenCalledOnce();
    expect(verify).toHaveBeenCalledTimes(2);
  });

  it("aborts verification and releases its navigation guard on unmount", async () => {
    const user = userEvent.setup();
    const pending = deferred<FileVerification>();
    const verify = vi.fn().mockReturnValue(pending.promise);
    const guard = vi.fn();
    const { unmount } = render(<BatchVerifyWorkflow health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(inspection())}
      verify={verify} onPendingResultsChange={guard} />);
    await prepare(user, [file(), file()]);
    await user.click(screen.getByRole("button", { name: "Verify batch" }));
    unmount();
    expect(verify.mock.calls[0][3].aborted).toBe(true);
    expect(guard).toHaveBeenLastCalledWith(false);
    await act(async () => pending.resolve(report()));
    expect(verify).toHaveBeenCalledOnce();
  });
});
