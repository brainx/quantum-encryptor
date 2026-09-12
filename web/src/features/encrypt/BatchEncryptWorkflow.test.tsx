import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type DownloadResult } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { BatchEncryptWorkflow } from "./BatchEncryptWorkflow";

const FINGERPRINT = `QE1-SHA3-256:${"a".repeat(64)}`;

function publicKeyInspection() {
  return {
    ok: true,
    keyInfo: { kem: READY_HEALTH.kem, key_type: "public" as const, public_key_fingerprint: FINGERPRINT },
    display: { "Public Key Fingerprint": FINGERPRINT }
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}

function ciphertext(filename = "report.txt.pqc"): DownloadResult {
  return { filename, blob: new Blob(["ciphertext"]) };
}

async function prepareBatch(user: ReturnType<typeof userEvent.setup>, files = [new File(["report"], "report.txt")]) {
  await user.upload(screen.getByLabelText("Files to encrypt"), files);
  await user.upload(screen.getByLabelText("Recipient public key"), new File(["PEM"], "recipient.pem"));
  await screen.findByText("Compatible public key");
}

describe("BatchEncryptWorkflow", () => {
  it("adds selected and dropped files, removes files, and allows selecting them again", async () => {
    const user = userEvent.setup();
    render(<BatchEncryptWorkflow health={READY_HEALTH} />);
    const first = new File(["first"], "first.txt");
    const second = new File(["second"], "second.txt");
    const third = new File(["third"], "third.txt");
    const input = screen.getByLabelText("Files to encrypt");

    expect(input).toHaveAttribute("multiple");
    await user.upload(input, [first, second]);
    expect(input).toHaveValue("");
    fireEvent.drop(input.closest("label")!, { dataTransfer: { files: [third] } });
    expect(within(screen.getByRole("list", { name: "Selected files" })).getAllByRole("listitem")).toHaveLength(3);

    await user.click(screen.getByRole("button", { name: "Remove first.txt" }));
    expect(screen.queryByRole("button", { name: "Remove first.txt" })).not.toBeInTheDocument();
    await user.upload(input, first);
    expect(screen.getByRole("button", { name: "Remove first.txt" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Remove third.txt" })).toBeVisible();
  });

  it.each([
    [Array.from({ length: 26 }, (_, index) => new File(["a"], `${index}.txt`)), READY_HEALTH],
    [[new File(["abc"], "a.txt"), new File(["de"], "b.txt")], { ...READY_HEALTH, maxFileBytes: 4 }],
    [[new File(["abcde"], "large.txt")], { ...READY_HEALTH, maxFileBytes: 4 }]
  ])("rejects an oversized selection before adding any files (%#)", async (files, health) => {
    const user = userEvent.setup();
    const encrypt = vi.fn();
    render(<BatchEncryptWorkflow encrypt={encrypt} health={health} />);

    await user.upload(screen.getByLabelText("Files to encrypt"), files);

    expect(screen.getByRole("alert")).toHaveTextContent("Files were not added.");
    expect(screen.queryByRole("list", { name: "Selected files" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Encrypt batch" })).toBeDisabled();
    expect(encrypt).not.toHaveBeenCalled();
  });

  it("preserves the existing selection when added files exceed the total limit", async () => {
    const user = userEvent.setup();
    render(<BatchEncryptWorkflow health={{ ...READY_HEALTH, maxFileBytes: 4 }} />);
    const input = screen.getByLabelText("Files to encrypt");
    await user.upload(input, new File(["abc"], "accepted.txt"));

    fireEvent.drop(input.closest("label")!, { dataTransfer: { files: [new File(["de"], "rejected.txt")] } });

    expect(screen.getByRole("alert")).toHaveTextContent("Files were not added.");
    expect(screen.getByRole("button", { name: "Remove accepted.txt" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Remove rejected.txt" })).not.toBeInTheDocument();
  });

  it.each([
    [{ kem: READY_HEALTH.kem, key_type: "private" }, "A public key is required to encrypt files."],
    [{ kem: "Kyber768", key_type: "public", public_key_fingerprint: FINGERPRINT }, `This public key uses Kyber768; encryption requires ${READY_HEALTH.kem}.`],
    [{ kem: READY_HEALTH.kem, key_type: "public" }, "The recipient public key did not provide a valid fingerprint."],
    [{ kem: READY_HEALTH.kem, key_type: "public", public_key_fingerprint: `QE1-SHA3-256:${"A".repeat(64)}` }, "The recipient public key did not provide a valid fingerprint."],
    [{ kem: READY_HEALTH.kem, key_type: "public", public_key_fingerprint: `${FINGERPRINT}\n` }, "The recipient public key did not provide a valid fingerprint."]
  ])("blocks an invalid recipient key (%#)", async (keyInfo, message) => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue({ ok: true, keyInfo, display: {} });
    const encrypt = vi.fn();
    render(<BatchEncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} />);

    await user.upload(screen.getByLabelText("Files to encrypt"), new File(["report"], "report.txt"));
    await user.upload(screen.getByLabelText("Recipient public key"), new File(["PEM"], "recipient.pem"));

    expect(await screen.findByText(message)).toBeVisible();
    expect(screen.getByRole("button", { name: "Encrypt batch" })).toBeDisabled();
    expect(screen.queryByText(FINGERPRINT)).not.toBeInTheDocument();
    expect(encrypt).not.toHaveBeenCalled();
  });

  it("does not reuse a prior key inspection while the recipient changes", async () => {
    const user = userEvent.setup();
    const nextInspection = deferred<ReturnType<typeof publicKeyInspection>>();
    const inspect = vi.fn().mockResolvedValueOnce(publicKeyInspection()).mockReturnValueOnce(nextInspection.promise);
    render(<BatchEncryptWorkflow health={READY_HEALTH} inspect={inspect} />);
    await prepareBatch(user);
    expect(screen.getByRole("button", { name: "Encrypt batch" })).toBeEnabled();

    await user.upload(screen.getByLabelText("Recipient public key"), new File(["next"], "next.pem"));

    expect(screen.getByRole("button", { name: "Encrypt batch" })).toBeDisabled();
    expect(screen.queryByText(FINGERPRINT)).not.toBeInTheDocument();
    expect(screen.getByText("Inspecting recipient key.")).toBeVisible();
  });

  it("retains ciphertext for explicit downloads and clears the batch for a new selection", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const encrypt = vi.fn((_file: File, _key: File, outputFilename: string) => Promise.resolve(ciphertext(outputFilename)));
    const save = vi.fn();
    const onPendingResultsChange = vi.fn();
    render(<BatchEncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={save} onPendingResultsChange={onPendingResultsChange} />);
    await prepareBatch(user, [new File(["a"], "a.txt"), new File(["b"], "b.txt")]);

    expect(screen.getByText(FINGERPRINT)).toBeVisible();
    expect(screen.getByText(/compare this complete fingerprint with the recipient/i)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Encrypt batch" }));

    const secondDownload = await screen.findByRole("button", { name: "Download b.txt.pqc" });
    expect(screen.getByText("2 of 2 files processed · 2 encrypted · 0 failed · 0 cancelled")).toBeVisible();
    expect(save).not.toHaveBeenCalled();
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);
    expect(screen.getByLabelText("Files to encrypt")).toBeDisabled();
    expect(screen.getByLabelText("Recipient public key")).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Download a.txt.pqc" }));
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ filename: "a.txt.pqc" }));
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);
    await user.click(secondDownload);
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(false);
    expect(screen.getAllByText("Download started")).toHaveLength(2);
    expect(encrypt).toHaveBeenCalledTimes(2);

    await user.click(screen.getByRole("button", { name: "Clear batch" }));
    expect(screen.queryByRole("region", { name: "Batch results" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Files to encrypt")).toBeEnabled();
    expect(screen.getByLabelText("Recipient public key")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Encrypt batch" })).toBeDisabled();
  });

  it("retries a failed download from retained ciphertext without encrypting again", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const result = ciphertext();
    const encrypt = vi.fn().mockResolvedValue(result);
    const save = vi.fn().mockImplementationOnce(() => { throw new TypeError("private browser detail"); });
    const onPendingResultsChange = vi.fn();
    render(<BatchEncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={save} onPendingResultsChange={onPendingResultsChange} />);
    await prepareBatch(user);
    await user.click(screen.getByRole("button", { name: "Encrypt batch" }));
    const downloadButton = await screen.findByRole("button", { name: "Download report.txt.pqc" });

    await user.click(downloadButton);

    expect(screen.getByRole("alert")).toHaveTextContent("The download could not start. Try downloading this file again.");
    expect(screen.queryByText(/private browser detail/)).not.toBeInTheDocument();
    expect(screen.queryByText("Download started")).not.toBeInTheDocument();
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);
    await user.click(downloadButton);
    expect(save).toHaveBeenNthCalledWith(1, result);
    expect(save).toHaveBeenNthCalledWith(2, result);
    expect(encrypt).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("Download started")).toBeVisible();
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(false);
  });

  it("cancels remaining files while retaining completed downloads", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const active = deferred<DownloadResult>();
    const encrypt = vi.fn().mockResolvedValueOnce(ciphertext("first.txt.pqc")).mockReturnValueOnce(active.promise);
    const save = vi.fn();
    render(<BatchEncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} save={save} />);
    await prepareBatch(user, [new File(["1"], "first.txt"), new File(["2"], "second.txt"), new File(["3"], "third.txt")]);
    await user.click(screen.getByRole("button", { name: "Encrypt batch" }));
    await waitFor(() => expect(encrypt).toHaveBeenCalledTimes(2));

    expect(screen.getByLabelText("Files to encrypt")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Clear batch" })).toBeDisabled();
    fireEvent.drop(screen.getByLabelText("Files to encrypt").closest("label")!, {
      dataTransfer: { files: [new File(["ignored"], "ignored.txt")] }
    });
    expect(screen.getByText("3 files · 3 B")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Cancel batch" }));
    expect(encrypt.mock.calls[1]?.[3].aborted).toBe(true);
    await act(async () => { active.resolve(ciphertext("second.txt.pqc")); await active.promise; });

    expect(screen.getByText("3 of 3 files processed · 1 encrypted · 0 failed · 2 cancelled")).toBeVisible();
    expect(screen.getAllByText("Cancelled")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Download first.txt.pqc" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Download second.txt.pqc" })).not.toBeInTheDocument();
    expect(encrypt).toHaveBeenCalledTimes(2);
    expect(save).not.toHaveBeenCalled();
  });

  it("shows a safe failed-file error without automatically retrying", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(publicKeyInspection());
    const encrypt = vi.fn().mockRejectedValue(new ApiError(500, "internal_error", "private server detail"));
    render(<BatchEncryptWorkflow encrypt={encrypt} health={READY_HEALTH} inspect={inspect} />);
    await prepareBatch(user);
    await user.click(screen.getByRole("button", { name: "Encrypt batch" }));

    expect(await screen.findByText("Failed")).toBeVisible();
    expect(screen.getByText("1 of 1 files processed · 0 encrypted · 1 failed · 0 cancelled")).toBeVisible();
    expect(screen.getByRole("alert")).not.toHaveTextContent("private server detail");
    expect(encrypt).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: /download/i })).not.toBeInTheDocument();
  });

  it.each(["cleared", "unmounted"])("clears pending-result notification when an undownloaded batch is %s", async (action) => {
    const user = userEvent.setup();
    const onPendingResultsChange = vi.fn();
    const { unmount } = render(<BatchEncryptWorkflow
      encrypt={vi.fn().mockResolvedValue(ciphertext())}
      health={READY_HEALTH}
      inspect={vi.fn().mockResolvedValue(publicKeyInspection())}
      onPendingResultsChange={onPendingResultsChange}
    />);
    await prepareBatch(user);
    await user.click(screen.getByRole("button", { name: "Encrypt batch" }));
    await screen.findByRole("button", { name: "Download report.txt.pqc" });
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);

    if (action === "cleared") {
      await user.click(screen.getByRole("button", { name: "Clear batch" }));
    } else {
      unmount();
    }

    expect(onPendingResultsChange).toHaveBeenLastCalledWith(false);
  });
});
