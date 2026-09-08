import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApiError, type DownloadResult } from "../../api";
import { READY_HEALTH } from "../../test/fixtures";
import { BatchDecryptWorkflow } from "./BatchDecryptWorkflow";

const PASSWORD = "correct horse battery staple";

function privateKeyInspection() {
  return {
    ok: true,
    keyInfo: { kem: READY_HEALTH.kem, key_type: "private" as const, private_key_encrypted: true, private_key_format_version: 3 },
    display: { "Key Type": "Encrypted private key" }
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}

function plaintext(filename = "report.txt"): DownloadResult {
  return { filename, blob: new Blob(["plaintext"]) };
}

async function prepareBatch(user: ReturnType<typeof userEvent.setup>, files = [new File(["encrypted report"], "report.txt.pqc")]) {
  await user.upload(screen.getByLabelText("Files to decrypt"), files);
  await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "recipient.pem"));
  await screen.findByText("Supported encrypted private key; match not yet verified");
  await user.type(screen.getByLabelText("Private key password"), PASSWORD);
}

describe("BatchDecryptWorkflow", () => {
  it("adds selected and dropped files, removes files, and allows selecting them again", async () => {
    const user = userEvent.setup();
    render(<BatchDecryptWorkflow health={READY_HEALTH} />);
    const first = new File(["first"], "first.txt.pqc");
    const second = new File(["second"], "second.txt.pqc");
    const third = new File(["third"], "third.txt.pqc");
    const input = screen.getByLabelText("Files to decrypt");

    expect(input).toHaveAttribute("multiple");
    await user.upload(input, [first, second]);
    expect(input).toHaveValue("");
    fireEvent.drop(input.closest("label")!, { dataTransfer: { files: [third] } });
    expect(within(screen.getByRole("list", { name: "Selected files" })).getAllByRole("listitem")).toHaveLength(3);

    await user.click(screen.getByRole("button", { name: "Remove first.txt.pqc" }));
    expect(screen.queryByRole("button", { name: "Remove first.txt.pqc" })).not.toBeInTheDocument();
    await user.upload(input, first);
    expect(screen.getByRole("button", { name: "Remove first.txt.pqc" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Remove third.txt.pqc" })).toBeVisible();
  });

  it.each([
    [Array.from({ length: 26 }, (_, index) => new File(["a"], `${index}.txt.pqc`)), READY_HEALTH],
    [[new File(["abc"], "a.txt.pqc"), new File(["de"], "b.txt.pqc")], { ...READY_HEALTH, maxEncryptedFileBytes: 4 }],
    [[new File(["abcde"], "large.txt.pqc")], { ...READY_HEALTH, maxEncryptedFileBytes: 4 }]
  ])("rejects an oversized selection before adding any files (%#)", async (files, health) => {
    const user = userEvent.setup();
    const decrypt = vi.fn();
    render(<BatchDecryptWorkflow decrypt={decrypt} health={health} />);

    await user.upload(screen.getByLabelText("Files to decrypt"), files);

    expect(screen.getByRole("alert")).toHaveTextContent("Files were not added.");
    expect(screen.queryByRole("list", { name: "Selected files" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decrypt batch" })).toBeDisabled();
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("preserves the existing selection when added files exceed the total limit", async () => {
    const user = userEvent.setup();
    render(<BatchDecryptWorkflow health={{ ...READY_HEALTH, maxEncryptedFileBytes: 4 }} />);
    const input = screen.getByLabelText("Files to decrypt");
    await user.upload(input, new File(["abc"], "accepted.txt.pqc"));

    fireEvent.drop(input.closest("label")!, { dataTransfer: { files: [new File(["de"], "rejected.txt.pqc")] } });

    expect(screen.getByRole("alert")).toHaveTextContent("Files were not added.");
    expect(screen.getByRole("button", { name: "Remove accepted.txt.pqc" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Remove rejected.txt.pqc" })).not.toBeInTheDocument();
  });

  it("uses the encrypted-file limit so supported ciphertext overhead is accepted", async () => {
    const user = userEvent.setup();
    render(<BatchDecryptWorkflow health={{ ...READY_HEALTH, maxFileBytes: 2, maxEncryptedFileBytes: 4 }} />);

    await user.upload(screen.getByLabelText("Files to decrypt"), new File(["abcd"], "valid.pqc"));

    expect(screen.getByRole("button", { name: "Remove valid.pqc" })).toBeVisible();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it.each([
    { kem: READY_HEALTH.kem, key_type: "public", public_key_fingerprint: "public fingerprint" },
    { kem: READY_HEALTH.kem, key_type: "private", private_key_encrypted: false },
    { kem: READY_HEALTH.kem, key_type: "private" }
  ])("rejects public or unencrypted private-key metadata (%#)", async (keyInfo) => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue({ ok: true, keyInfo, display: {} });
    const decrypt = vi.fn();
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} />);
    await user.upload(screen.getByLabelText("Files to decrypt"), new File(["encrypted"], "report.txt.pqc"));
    await user.upload(screen.getByLabelText("Private key"), new File(["PEM"], "key.pem"));
    await user.type(screen.getByLabelText("Private key password"), PASSWORD);

    expect(await screen.findByText("A supported encrypted private key is required to decrypt files.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Decrypt batch" })).toBeDisabled();
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("accepts supported legacy private keys without requiring a public fingerprint", async () => {
    const user = userEvent.setup();
    const inspection = privateKeyInspection();
    inspection.keyInfo.kem = "ML-KEM-768";
    inspection.keyInfo.private_key_format_version = 2;
    const decrypt = vi.fn().mockResolvedValue(plaintext());
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(inspection)} />);
    await prepareBatch(user);

    expect(screen.getByText("ML-KEM-768")).toBeVisible();
    expect(screen.getByRole("button", { name: "Decrypt batch" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));
    expect(await screen.findByRole("button", { name: "Download report.txt" })).toBeVisible();
  });

  it("clears the password and prior metadata when the selected private key changes", async () => {
    const user = userEvent.setup();
    const pending = deferred<ReturnType<typeof privateKeyInspection>>();
    const inspect = vi.fn().mockResolvedValueOnce(privateKeyInspection()).mockReturnValueOnce(pending.promise);
    render(<BatchDecryptWorkflow health={READY_HEALTH} inspect={inspect} />);
    await prepareBatch(user);
    await user.upload(screen.getByLabelText("Private key"), new File(["next"], "next.pem"));

    expect(screen.getByLabelText("Private key password")).toHaveValue("");
    expect(screen.getByText("Inspecting private key.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Decrypt batch" })).toBeDisabled();
    expect(screen.queryByText("Supported encrypted private key; match not yet verified")).not.toBeInTheDocument();
  });

  it("retains plaintext for explicit downloads and clears the batch for a new selection", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const decrypt = vi.fn((_file: File, _key: File, _password: string, outputFilename: string) => Promise.resolve(plaintext(outputFilename)));
    const save = vi.fn();
    const onPendingResultsChange = vi.fn();
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={save} onPendingResultsChange={onPendingResultsChange} />);
    await prepareBatch(user, [new File(["a"], "a.txt.pqc"), new File(["b"], "b.txt.pqc")]);

    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));

    const secondDownload = await screen.findByRole("button", { name: "Download b.txt" });
    expect(screen.getByText("2 of 2 files processed · 2 decrypted · 0 failed · 0 cancelled")).toBeVisible();
    expect(save).not.toHaveBeenCalled();
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);
    expect(screen.getByLabelText("Files to decrypt")).toBeDisabled();
    expect(screen.getByLabelText("Private key")).toBeDisabled();
    expect(screen.getByLabelText("Private key password")).toHaveValue("");
    expect(screen.queryByText("plaintext")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Download a.txt" }));
    expect(save).toHaveBeenCalledWith(expect.objectContaining({ filename: "a.txt" }));
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);
    await user.click(secondDownload);
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);
    expect(screen.getAllByText("Download started")).toHaveLength(2);
    expect(decrypt).toHaveBeenCalledTimes(2);

    await user.click(screen.getByRole("button", { name: "Clear batch" }));
    expect(screen.queryByRole("region", { name: "Batch results" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Files to decrypt")).toBeEnabled();
    expect(screen.getByLabelText("Private key")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Decrypt batch" })).toBeDisabled();
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(false);
  });

  it("clears the password field immediately while using the captured password for each sequential request", async () => {
    const user = userEvent.setup();
    const active = deferred<DownloadResult>();
    const decrypt = vi.fn().mockReturnValueOnce(active.promise).mockResolvedValueOnce(plaintext("second.txt"));
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(privateKeyInspection())} />);
    await prepareBatch(user, [new File(["a"], "first.txt.pqc"), new File(["b"], "second.txt.pqc")]);

    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));

    expect(screen.getByLabelText("Private key password")).toHaveValue("");
    expect(screen.getByLabelText("Private key password")).toBeDisabled();
    expect(decrypt).toHaveBeenCalledTimes(1);
    expect(decrypt).toHaveBeenLastCalledWith(
      expect.objectContaining({ name: "first.txt.pqc" }),
      expect.objectContaining({ name: "recipient.pem" }),
      PASSWORD,
      "first.txt",
      expect.any(AbortSignal)
    );
    expect(screen.queryByRole("button", { name: /download/i })).not.toBeInTheDocument();
    await act(async () => { active.resolve(plaintext("first.txt")); await active.promise; });

    expect(await screen.findByRole("button", { name: "Download second.txt" })).toBeVisible();
    expect(decrypt).toHaveBeenCalledTimes(2);
    expect(decrypt.mock.calls.map((call) => call[2])).toEqual([PASSWORD, PASSWORD]);
    expect(screen.getByLabelText("Private key password")).toHaveValue("");
  });

  it("restores extensions and deduplicates normalized output filenames", async () => {
    const user = userEvent.setup();
    const decrypt = vi.fn((_file: File, _key: File, _password: string, name: string) => Promise.resolve(plaintext(name)));
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(privateKeyInspection())} />);
    const names = ["report.txt.pqc", "REPORT.TXT.PQC", "a?.txt.pqc", "a*.txt.pqc", ".pqc", "photo_encrypted.pqc"];
    await prepareBatch(user, names.map((name) => new File(["ciphertext"], name)));

    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));

    await screen.findByText("6 of 6 files processed · 6 decrypted · 0 failed · 0 cancelled");
    expect(decrypt.mock.calls.map((call) => call[3])).toEqual([
      "report.txt", "REPORT-2.TXT", "a_.txt", "a_-2.txt", "decrypted.bin", "photo"
    ]);
  });

  it.each(["decryption_failed", "private_key_failed"])("keeps an unauthenticated file unavailable after %s and continues without retry", async (code) => {
    const user = userEvent.setup();
    const decrypt = vi.fn()
      .mockRejectedValueOnce(new ApiError(400, code, "raw private key failure detail"))
      .mockResolvedValueOnce(plaintext("good.txt"));
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(privateKeyInspection())} />);
    await prepareBatch(user, [new File(["bad"], "bad.txt.pqc"), new File(["good"], "good.txt.pqc")]);

    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));

    expect(await screen.findByRole("button", { name: "Download good.txt" })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent("The file could not be authenticated. Check the encrypted file, private key, and password.");
    expect(screen.getByRole("alert")).not.toHaveTextContent("raw private key failure detail");
    expect(screen.queryByRole("button", { name: "Download bad.txt" })).not.toBeInTheDocument();
    expect(decrypt.mock.calls.map((call) => call[0].name)).toEqual(["bad.txt.pqc", "good.txt.pqc"]);
    expect(screen.getByLabelText("Private key password")).toHaveValue("");
  });

  it("retries a failed download from retained plaintext without decrypting again", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const result = plaintext();
    const decrypt = vi.fn().mockResolvedValue(result);
    const save = vi.fn().mockImplementationOnce(() => { throw new TypeError("private browser detail"); });
    const onPendingResultsChange = vi.fn();
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={save} onPendingResultsChange={onPendingResultsChange} />);
    await prepareBatch(user);
    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));
    const downloadButton = await screen.findByRole("button", { name: "Download report.txt" });

    await user.click(downloadButton);

    expect(screen.getByRole("alert")).toHaveTextContent("The download could not start. Try downloading this file again.");
    expect(screen.queryByText(/private browser detail/)).not.toBeInTheDocument();
    expect(screen.queryByText("Download started")).not.toBeInTheDocument();
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);
    await user.click(downloadButton);
    expect(save).toHaveBeenNthCalledWith(1, result);
    expect(save).toHaveBeenNthCalledWith(2, result);
    expect(decrypt).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("Download started")).toBeVisible();
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);
  });

  it("cancels remaining files while retaining completed downloads", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const active = deferred<DownloadResult>();
    const decrypt = vi.fn().mockResolvedValueOnce(plaintext("first.txt")).mockReturnValueOnce(active.promise);
    const save = vi.fn();
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} save={save} />);
    await prepareBatch(user, [new File(["1"], "first.txt.pqc"), new File(["2"], "second.txt.pqc"), new File(["3"], "third.txt.pqc")]);
    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));
    await waitFor(() => expect(decrypt).toHaveBeenCalledTimes(2));

    expect(screen.getByLabelText("Files to decrypt")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Clear batch" })).toBeDisabled();
    fireEvent.drop(screen.getByLabelText("Files to decrypt").closest("label")!, {
      dataTransfer: { files: [new File(["ignored"], "ignored.txt")] }
    });
    expect(screen.getByText("3 files · 3 B")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Cancel batch" }));
    expect(decrypt.mock.calls[1]?.[4].aborted).toBe(true);
    await act(async () => { active.resolve(plaintext("second.txt")); await active.promise; });

    expect(screen.getByText("3 of 3 files processed · 1 decrypted · 0 failed · 2 cancelled")).toBeVisible();
    expect(screen.getAllByText("Cancelled")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Download first.txt" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Download second.txt" })).not.toBeInTheDocument();
    expect(decrypt).toHaveBeenCalledTimes(2);
    expect(save).not.toHaveBeenCalled();
  });

  it("shows a safe failed-file error without automatically retrying", async () => {
    const user = userEvent.setup();
    const inspect = vi.fn().mockResolvedValue(privateKeyInspection());
    const decrypt = vi.fn().mockRejectedValue(new ApiError(500, "internal_error", "private server detail"));
    render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={inspect} />);
    await prepareBatch(user);
    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));

    expect(await screen.findByText("Failed")).toBeVisible();
    expect(screen.getByText("1 of 1 files processed · 0 decrypted · 1 failed · 0 cancelled")).toBeVisible();
    expect(screen.getByRole("alert")).not.toHaveTextContent("private server detail");
    expect(decrypt).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: /download/i })).not.toBeInTheDocument();
  });

  it.each(["cleared", "unmounted"])("clears pending-result notification when an undownloaded batch is %s", async (action) => {
    const user = userEvent.setup();
    const onPendingResultsChange = vi.fn();
    const { unmount } = render(<BatchDecryptWorkflow
      decrypt={vi.fn().mockResolvedValue(plaintext())}
      health={READY_HEALTH}
      inspect={vi.fn().mockResolvedValue(privateKeyInspection())}
      onPendingResultsChange={onPendingResultsChange}
    />);
    await prepareBatch(user);
    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));
    await screen.findByRole("button", { name: "Download report.txt" });
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(true);

    if (action === "cleared") {
      await user.click(screen.getByRole("button", { name: "Clear batch" }));
    } else {
      unmount();
    }

    expect(onPendingResultsChange).toHaveBeenLastCalledWith(false);
  });

  it("aborts on unmount and ignores plaintext returned after leaving", async () => {
    const user = userEvent.setup();
    const active = deferred<DownloadResult>();
    const decrypt = vi.fn().mockReturnValue(active.promise);
    const onPendingResultsChange = vi.fn();
    const { unmount } = render(<BatchDecryptWorkflow decrypt={decrypt} health={READY_HEALTH} inspect={vi.fn().mockResolvedValue(privateKeyInspection())} onPendingResultsChange={onPendingResultsChange} />);
    await prepareBatch(user);
    await user.click(screen.getByRole("button", { name: "Decrypt batch" }));

    unmount();
    await act(async () => { active.resolve(plaintext()); await active.promise; });

    expect(decrypt.mock.calls[0]?.[4].aborted).toBe(true);
    expect(onPendingResultsChange).not.toHaveBeenCalledWith(true);
    expect(onPendingResultsChange).toHaveBeenLastCalledWith(false);
  });
});
