import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import AxeBuilder from "@axe-core/playwright";
import { chromium } from "playwright";

const baseUrl = process.env.UI_NATIVE_URL ?? "http://127.0.0.1:4000/";
const password = "correct horse battery staple";
const updatedPassword = "new correct horse battery staple";
const inputBytes = Buffer.from("native browser round trip");
const screenshotDirectory = process.argv.includes("--screenshots")
  ? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../docs/screenshots")
  : null;

async function capture(page, filename) {
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true,
    "The workflow must fit its viewport without horizontal scrolling.");
  const accessibility = await new AxeBuilder({ page }).analyze();
  assert.deepEqual(accessibility.violations.map(({ id, impact }) => ({ id, impact })), [],
    "The native workflow must pass automated accessibility checks.");
  if (screenshotDirectory) {
    await mkdir(screenshotDirectory, { recursive: true });
    await page.screenshot({ path: path.join(screenshotDirectory, filename), fullPage: true });
  }
}

async function selectExpectedRecipient(page, fingerprint, submitLabel) {
  const input = page.getByLabel("Expected recipient fingerprint (optional)", { exact: true });
  const submit = page.getByRole("button", { name: submitLabel, exact: true });
  const different = `${fingerprint.slice(0, -1)}${fingerprint.endsWith("0") ? "1" : "0"}`;
  await input.fill(fingerprint);
  await page.getByText("Expected fingerprint matches the selected public key.", { exact: true }).waitFor();
  assert.equal(await submit.isEnabled(), true, "The matching key must be ready before testing a mismatch.");
  await input.fill(different);
  await page.getByText("The expected fingerprint does not match the selected public key. Check the key and trusted fingerprint before encrypting.", { exact: true }).waitFor();
  assert.equal(await submit.isDisabled(), true, "A mismatching expected recipient must block submission.");
  await input.fill(fingerprint);
  await page.getByText("Expected fingerprint matches the selected public key.", { exact: true }).waitFor();
  assert.equal(await submit.isEnabled(), true, "A matching expected recipient must permit submission.");
}

async function checkServerRecipientGuard(page, publicKeyPath, fingerprint) {
  const different = `${fingerprint.slice(0, -1)}${fingerprint.endsWith("0") ? "1" : "0"}`;
  const request = page.context().request;
  const headers = { Origin: new URL(baseUrl).origin };
  const publicKey = { name: "recipient-public.pem", mimeType: "application/x-pem-file", buffer: await readFile(publicKeyPath) };
  const response = await page.context().request.post(new URL("/api/files/encrypt", baseUrl).href, {
    headers,
    multipart: {
      file: { name: "sample.txt", mimeType: "text/plain", buffer: inputBytes },
      public_key: publicKey,
      expected_recipient_fingerprint: different
    }
  });
  assert.equal(response.status(), 400, "The backend must independently reject a mismatching recipient.");
  assert.equal((await response.json()).error_code, "recipient_fingerprint_mismatch");

  const reserved = await request.post(new URL("/api/jobs", baseUrl).href, {
    headers, multipart: { mode: "encrypt", filename: "sample.txt", size: String(inputBytes.length) }
  });
  assert.equal(reserved.ok(), true);
  const { job } = await reserved.json();
  const jobUrl = (action) => new URL(`/api/jobs/${encodeURIComponent(job.id)}/${action}`, baseUrl).href;
  try {
    const uploaded = await request.put(jobUrl("upload"), {
      headers: { ...headers, "Content-Type": "application/octet-stream" }, data: inputBytes
    });
    assert.equal(uploaded.ok(), true);
    const started = await request.post(jobUrl("start"), {
      headers, multipart: { key: publicKey, expected_recipient_fingerprint: different }
    });
    assert.equal(started.ok(), true);
    let state = (await started.json()).job;
    for (let attempt = 0; state.state === "running" && attempt < 50; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      const status = await request.post(jobUrl("status"), { headers });
      assert.equal(status.ok(), true);
      state = (await status.json()).job;
    }
    assert.equal(state.state, "failed", "A wrong expected recipient must fail the native large-file job.");
    assert.equal(state.error.code, "recipient_fingerprint_mismatch");
    assert.equal(state.result, undefined, "A mismatching recipient must not publish an encrypted result.");
  } finally {
    await request.post(jobUrl("cancel"), { headers });
    const cleared = await request.post(jobUrl("clear"), { headers });
    assert.equal(cleared.ok(), true, "The recipient-check fixture must release its temporary files.");
  }
}

function assertReadyHealth(health) {
  const requiredCapabilities = ["generate", "encrypt", "decrypt"];
  const isReady = Boolean(
    health?.ok &&
      health.backendReady &&
      requiredCapabilities.every((capability) => health.capabilities?.[capability]?.available)
  );

  assert.equal(isReady, true, "The native local engine is not ready for key generation, encryption, and decryption.");
}

async function saveDownload(download, destination) {
  await download.saveAs(destination);
  return destination;
}

async function downloadFromButton(page, name, destination) {
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name, exact: true }).click();
  return saveDownload(await downloadPromise, destination);
}

async function decryptFromUi(page, encryptedPath, privateKeyPath, decryptedPath, privateKeyPassword = password) {
  await page.getByRole("button", { name: "Decrypt", exact: true }).click();
  await page.getByRole("heading", { name: "Decrypt a file" }).waitFor();
  await page.getByLabel("Encrypted file").setInputFiles(encryptedPath);
  await page.getByLabel("Private key", { exact: true }).setInputFiles(privateKeyPath);
  await page
    .getByText("Supported encrypted private key; match not yet verified", { exact: true })
    .waitFor({ state: "visible" });
  await page.getByLabel("Private key password", { exact: true }).fill(privateKeyPassword);
  const decryptedDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Decrypt file" }).click();
  await saveDownload(await decryptedDownload, decryptedPath);
  await page.getByText("File decrypted", { exact: true }).waitFor({ state: "visible" });
}

async function runBatchRoundTrips(page, temporaryDirectory, publicKeyPath, privateKeyPath, fingerprint) {
  const inputs = [
    { filename: "batch-text.txt", bytes: Buffer.from("Batch browser round trip\nUTF-8: café, 日本語, 🔐\n") },
    { filename: "batch-binary.bin", bytes: Buffer.from(Array.from({ length: 512 }, (_, index) => index % 256)) }
  ];
  for (const input of inputs) {
    await writeFile(path.join(temporaryDirectory, input.filename), input.bytes);
  }

  const downloads = [];
  const recordDownload = (download) => downloads.push(download);
  page.on("download", recordDownload);
  try {
    await page.getByRole("button", { name: "Batch encrypt", exact: true }).click();
    await page.getByRole("heading", { name: "Encrypt multiple files" }).waitFor();
    await page.getByLabel("Files to encrypt", { exact: true }).setInputFiles(
      inputs.map((input) => path.join(temporaryDirectory, input.filename))
    );
    await page.getByLabel("Recipient public key", { exact: true }).setInputFiles(publicKeyPath);
    await page.getByText("Compatible public key", { exact: true }).waitFor({ state: "visible" });
    await selectExpectedRecipient(page, fingerprint, "Encrypt batch");
    await page.getByRole("button", { name: "Encrypt batch", exact: true }).click();

    const results = page.getByRole("list", { name: "File encryption results" });
    for (const input of inputs) {
      await results.getByRole("button", { name: `Download ${input.filename}.pqc`, exact: true })
        .waitFor({ state: "visible" });
    }
    assert.equal(downloads.length, 0, "Batch encryption must wait for explicit per-file downloads.");

    for (const [index, input] of inputs.entries()) {
      await downloadFromButton(page, `Download ${input.filename}.pqc`, path.join(temporaryDirectory, `${input.filename}.pqc`));
      assert.equal(downloads.length, index + 1, "Each batch download button must download exactly one result.");
    }

    await page.getByRole("button", { name: "Batch decrypt", exact: true }).click();
    await page.getByRole("heading", { name: "Decrypt multiple files", exact: true }).waitFor();
    await page.getByLabel("Files to decrypt", { exact: true }).setInputFiles(
      inputs.map((input) => path.join(temporaryDirectory, `${input.filename}.pqc`))
    );
    await page.getByLabel("Private key", { exact: true }).setInputFiles(privateKeyPath);
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Decrypt batch", exact: true }).click();

    const decryptedResults = page.getByRole("list", { name: "File decryption results", exact: true });
    for (const input of inputs) {
      await decryptedResults.getByRole("button", { name: `Download ${input.filename}`, exact: true })
        .waitFor({ state: "visible" });
    }
    assert.equal(downloads.length, inputs.length, "Batch decryption must wait for explicit per-file downloads.");

    for (const [index, input] of inputs.entries()) {
      const decryptedPath = path.join(temporaryDirectory, `${input.filename}.decrypted`);
      await downloadFromButton(page, `Download ${input.filename}`, decryptedPath);
      assert.equal(downloads.length, inputs.length + index + 1, "Each batch decryption download button must download exactly one result.");
      assert.deepEqual(await readFile(decryptedPath), input.bytes, `The batch round trip changed ${input.filename}.`);
    }
    await page.getByRole("button", { name: "Clear batch", exact: true }).click();
    assert.equal(await page.getByRole("list", { name: "File decryption results", exact: true }).count(), 0);
  } finally {
    page.off("download", recordDownload);
  }
}

async function runPasswordChange(page, temporaryDirectory, privateKeyPath, encryptedPath) {
  const updatedKeyPath = path.join(temporaryDirectory, "updated-private.pem");
  const decryptedPath = path.join(temporaryDirectory, "updated-key-decrypted.txt");
  const downloads = [];
  const recordDownload = (download) => downloads.push(download);
  page.on("download", recordDownload);
  try {
    await page.getByRole("button", { name: "Change password", exact: true }).click();
    await page.getByRole("heading", { name: "Change private key password", exact: true }).waitFor();
    await page.getByLabel("Private key", { exact: true }).setInputFiles(privateKeyPath);
    await page.getByLabel("Current password", { exact: true }).fill(password);
    await page.getByLabel("New password", { exact: true }).fill(updatedPassword);
    await page.getByLabel("Confirm new password", { exact: true }).fill(updatedPassword);
    await page.getByRole("button", { name: "Change key password", exact: true }).click();
    await page.getByRole("button", { name: "Download updated private key", exact: true }).waitFor({ state: "visible" });
    assert.equal(downloads.length, 0, "The updated private key must wait for an explicit download.");
    await downloadFromButton(page, "Download updated private key", updatedKeyPath);
    assert.equal(downloads.length, 1, "The updated key download button must download exactly one key.");
    await page.getByRole("button", { name: "Clear updated key", exact: true }).click();
    assert.equal(await page.getByRole("button", { name: "Download updated private key", exact: true }).count(), 0);
  } finally {
    page.off("download", recordDownload);
  }

  await decryptFromUi(page, encryptedPath, updatedKeyPath, decryptedPath, updatedPassword);
  assert.deepEqual(await readFile(decryptedPath), inputBytes, "The updated private key changed the decrypted bytes.");

  downloads.length = 0;
  page.on("download", recordDownload);
  try {
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Decrypt file", exact: true }).click();
    await page.getByText("The file could not be authenticated. Check the encrypted file, private key, and password.", { exact: true })
      .waitFor({ state: "visible" });
    assert.equal(downloads.length, 0, "The original password must not decrypt with the updated private key.");
  } finally {
    page.off("download", recordDownload);
  }
}

async function runPublicKeyRecovery(page, temporaryDirectory, publicKeyPath, privateKeyPath) {
  const recoveredPath = path.join(temporaryDirectory, "recovered-public.pem");
  const downloads = [];
  const recordDownload = (download) => downloads.push(download);
  page.on("download", recordDownload);
  try {
    await page.getByRole("navigation", { name: "Workflows", exact: true })
      .getByRole("button", { name: "Recover public key", exact: true }).click();
    await page.getByRole("heading", { name: "Recover public key", exact: true }).waitFor();
    await page.getByLabel("Private key", { exact: true }).setInputFiles(privateKeyPath);
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    await page.getByLabel("Public key to compare (optional)", { exact: true }).setInputFiles(publicKeyPath);
    await page.getByRole("main").getByRole("button", { name: "Recover public key", exact: true }).click();
    await page.getByRole("button", { name: "Download public key", exact: true }).waitFor({ state: "visible" });
    await page.getByText("The supplied public key matches this private key.", { exact: true }).waitFor({ state: "visible" });
    assert.equal(downloads.length, 0, "The recovered public key must wait for an explicit download.");
    await downloadFromButton(page, "Download public key", recoveredPath);
    assert.equal(downloads.length, 1, "The public key download button must download exactly one key.");
    assert.deepEqual(await readFile(recoveredPath), await readFile(publicKeyPath), "The recovered public key differs from the generated public key.");
    await page.getByRole("button", { name: "Clear result", exact: true }).click();
    assert.equal(await page.getByRole("button", { name: "Download public key", exact: true }).count(), 0);
  } finally {
    page.off("download", recordDownload);
  }
}

async function runFileVerification(page, temporaryDirectory, privateKeyPath, encryptedPath) {
  const encryptedBytes = await readFile(encryptedPath);
  const tamperedBytes = Buffer.from(encryptedBytes);
  tamperedBytes[tamperedBytes.length - 1] ^= 1;
  const tamperedPath = path.join(temporaryDirectory, "tampered.pqc");
  await writeFile(tamperedPath, tamperedBytes);

  const downloads = [];
  const recordDownload = (download) => downloads.push(download);
  const apiResponse = (pathname) => page.waitForResponse((response) =>
    new URL(response.url()).pathname === pathname && response.request().method() === "POST"
  );
  page.on("download", recordDownload);
  try {
    await page.getByRole("navigation", { name: "Workflows", exact: true })
      .getByRole("button", { name: "Verify file", exact: true }).click();
    await page.getByRole("heading", { name: "Inspect and verify a file", exact: true }).waitFor();
    const inspectionResponse = apiResponse("/api/files/inspect");
    await page.getByLabel("Encrypted file", { exact: true }).setInputFiles(encryptedPath);
    const inspection = await (await inspectionResponse).json();
    assert.equal(inspection.ok, true, "Selecting a file must inspect its metadata automatically.");
    assert.equal(inspection.authenticated, false, "Metadata inspection must not claim file authentication.");
    assert.equal(inspection.metadata.totalBytes, encryptedBytes.length);
    await page.getByLabel("Private key", { exact: true }).setInputFiles(privateKeyPath);
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    const verificationResponse = apiResponse("/api/files/verify");
    await page.getByRole("main").getByRole("button", { name: "Verify file", exact: true }).click();
    const verification = await (await verificationResponse).json();
    assert.deepEqual(Object.keys(verification).sort(), ["bytesVerified", "formatVersion", "kem", "ok", "publicKeyFingerprint", "verified"],
      "Verification must return only an authentication report, never plaintext.");
    assert.equal(verification.ok, true);
    assert.equal(verification.verified, true);
    assert.equal(verification.bytesVerified, inputBytes.length);
    await page.getByText("File authenticated", { exact: true }).waitFor({ state: "visible" });
    await page.getByText(`${inputBytes.length.toLocaleString()} bytes authenticated.`, { exact: true }).waitFor({ state: "visible" });
    assert.equal(downloads.length, 0, "File verification must not start a plaintext download.");
    assert.equal((await page.getByRole("main").innerText()).includes(inputBytes.toString("utf8")), false,
      "File verification must not display the authenticated plaintext.");

    const tamperedInspectionResponse = apiResponse("/api/files/inspect");
    await page.getByLabel("Encrypted file", { exact: true }).setInputFiles(tamperedPath);
    const tamperedInspection = await (await tamperedInspectionResponse).json();
    assert.equal(tamperedInspection.ok, true, "Ciphertext tampering must still allow structural metadata inspection.");
    assert.equal(tamperedInspection.authenticated, false);
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    const rejectedVerificationResponse = apiResponse("/api/files/verify");
    await page.getByRole("main").getByRole("button", { name: "Verify file", exact: true }).click();
    const rejectedResponse = await rejectedVerificationResponse;
    assert.equal(rejectedResponse.status(), 400);
    const rejection = await rejectedResponse.json();
    assert.equal(rejection.ok, false);
    assert.equal(rejection.error_code, "verification_failed");
    await page.getByRole("main").getByRole("alert").waitFor({ state: "visible" });
    assert.equal(await page.getByText("File authenticated", { exact: true }).count(), 0);
    assert.equal(downloads.length, 0, "A tampered file must not start a plaintext download.");
    assert.equal((await page.getByRole("main").innerText()).includes(inputBytes.toString("utf8")), false);
  } finally {
    page.off("download", recordDownload);
  }
}

async function downloadLargeResult(page, destination) {
  const context = page.context();
  const watchedPages = new Set();
  let acceptDownload;
  let rejectDownload;
  const received = new Promise((resolve, reject) => { acceptDownload = resolve; rejectDownload = reject; });
  const timer = setTimeout(() => rejectDownload(new Error("The large-file attachment did not download.")), 30000);
  const onDownload = (download) => acceptDownload(download);
  const watch = (candidate) => { watchedPages.add(candidate); candidate.on("download", onDownload); };
  context.pages().forEach(watch);
  context.on("page", watch);
  try {
    await page.getByRole("button", { name: "Download result", exact: true }).click();
    await saveDownload(await received, destination);
  } finally {
    clearTimeout(timer);
    context.off("page", watch);
    for (const candidate of watchedPages) candidate.off("download", onDownload);
  }
}

async function runLargeFileRoundTrip(page, temporaryDirectory, publicKeyPath, privateKeyPath, fingerprint) {
  const plaintext = Buffer.alloc(2 * 1024 * 1024 + 17);
  for (let index = 0; index < plaintext.length; index += 1) plaintext[index] = index % 251;
  const inputPath = path.join(temporaryDirectory, "large-input.bin");
  const encryptedPath = path.join(temporaryDirectory, "large-input.bin.pqc");
  const decryptedPath = path.join(temporaryDirectory, "large-output.bin");
  await writeFile(inputPath, plaintext);
  const responses = [];
  const onResponse = (response) => {
    if (/\/api\/jobs\/[^/]+\/download$/.test(new URL(response.url()).pathname)) responses.push(response);
  };
  page.context().on("response", onResponse);
  try {
    await page.getByRole("navigation", { name: "Workflows", exact: true }).getByRole("button", { name: "Large files", exact: true }).click();
    await page.getByRole("heading", { name: "Large files", exact: true }).waitFor();
    await page.getByLabel("File to encrypt", { exact: true }).setInputFiles(inputPath);
    await page.getByLabel("Recipient public key", { exact: true }).setInputFiles(publicKeyPath);
    await selectExpectedRecipient(page, fingerprint, "Encrypt large file");
    await page.getByRole("button", { name: "Encrypt large file", exact: true }).click();
    await page.getByRole("button", { name: "Download result", exact: true }).waitFor();
    await capture(page, "custom-web-large-file-result.png");
    assert.equal(responses.length, 0, "Large-file encryption must wait for an explicit download.");
    await downloadLargeResult(page, encryptedPath);
    await page.getByText("Download requested. The browser controls whether it finishes.", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Clear temporary files", exact: true }).click();
    await page.getByRole("button", { name: "Encrypt large file", exact: true }).waitFor();

    await page.getByLabel("Operation", { exact: true }).selectOption("decrypt");
    await page.getByLabel("Encrypted file", { exact: true }).setInputFiles(encryptedPath);
    await page.getByLabel("Private key", { exact: true }).setInputFiles(privateKeyPath);
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Decrypt large file", exact: true }).click();
    assert.equal(await page.getByLabel("Private key password", { exact: true }).inputValue(), "");
    await page.getByRole("button", { name: "Download result", exact: true }).waitFor();
    assert.equal(responses.length, 1, "Large-file decryption must wait for an explicit download.");
    await downloadLargeResult(page, decryptedPath);
    assert.deepEqual(await readFile(decryptedPath), plaintext, "The large-file browser round trip changed the plaintext.");
    await page.getByRole("button", { name: "Clear temporary files", exact: true }).click();
    await page.getByRole("button", { name: "Decrypt large file", exact: true }).waitFor();

    await page.getByLabel("Operation", { exact: true }).selectOption("verify");
    await page.getByLabel("Encrypted file", { exact: true }).setInputFiles(encryptedPath);
    await page.getByLabel("Private key", { exact: true }).setInputFiles(privateKeyPath);
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Verify large file", exact: true }).click();
    await page.getByText("File authenticated", { exact: true }).waitFor();
    assert.equal(await page.getByRole("button", { name: "Download result", exact: true }).count(), 0);
    assert.equal(responses.length, 2, "Large-file verification must not download plaintext.");
    for (const response of responses) {
      assert.equal(response.status(), 200, "The authenticated large-file download must succeed.");
      assert.equal(response.request().method(), "POST");
      const headers = await response.request().allHeaders();
      assert.equal(headers.origin, new URL(baseUrl).origin, "Attachment navigation must preserve the trusted Origin.");
    }
    await page.getByRole("button", { name: "Clear temporary files", exact: true }).click();
    await page.getByRole("button", { name: "Verify large file", exact: true }).waitFor();
  } finally {
    page.context().off("response", onResponse);
  }
}

async function run() {
  let temporaryDirectory;
  let browser;

  try {
    temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "quantum-encryptor-native-ui-"));
    const inputPath = path.join(temporaryDirectory, "project-notes.txt");
    const publicKeyPath = path.join(temporaryDirectory, "recipient-public.pem");
    const privateKeyPath = path.join(temporaryDirectory, "private.pem");
    const encryptedPath = path.join(temporaryDirectory, "input_encrypted.pqc");
    const decryptedPath = path.join(temporaryDirectory, "input_decrypted.txt");
    await writeFile(inputPath, inputBytes);

    browser = await chromium.launch({ headless: true, executablePath: process.env.UI_BROWSER_EXECUTABLE });
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    // Chromium may omit file-backed multipart bodies from request events. Observe
    // only the public comparison field, forwarding every fetch unchanged.
    await page.addInitScript(() => {
      window.recipientChecks = [];
      const originalFetch = window.fetch;
      window.fetch = function (input, init) {
        const pathname = new URL(input instanceof Request ? input.url : input, location.href).pathname;
        if (init?.method === "POST" && init.body instanceof FormData &&
          (pathname === "/api/files/encrypt" || /^\/api\/jobs\/[^/]+\/start$/.test(pathname))) {
          window.recipientChecks.push({ pathname, expected: init.body.getAll("expected_recipient_fingerprint") });
        }
        return originalFetch.call(this, input, init);
      };
    });

    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await page.getByRole("heading", { name: "Encrypt a file" }).waitFor();

    const health = await page.evaluate(async () => {
      const response = await fetch("/api/health", { credentials: "same-origin" });
      if (!response.ok) return null;
      return response.json();
    });
    assertReadyHealth(health);
    assert.equal(health.supportsRecipientFingerprint, true, "The backend must enforce expected recipient fingerprints.");
    await page.getByText("Ready", { exact: true }).first().waitFor({ state: "visible" });

    await page.getByRole("button", { name: "Generate keys" }).click();
    await page.getByRole("heading", { name: "Generate keys" }).waitFor();
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    await page.getByLabel("Confirm private key password").fill(password);
    const generatedResponse = page.waitForResponse((response) =>
      new URL(response.url()).pathname === "/api/keys/generate" && response.request().method() === "POST"
    );
    await page.getByRole("button", { name: "Generate key pair" }).click();
    const fingerprint = (await (await generatedResponse).json()).publicKeyFingerprint;
    assert.match(fingerprint, /^QE1-SHA3-256:[0-9a-f]{64}$/);
    await page.getByText("Key pair generated", { exact: true }).waitFor({ state: "visible" });
    await downloadFromButton(page, "Download public key", publicKeyPath);
    await downloadFromButton(page, "Download encrypted private key", privateKeyPath);
    await page.getByRole("button", { name: "Clear generated keys" }).click();
    assert.equal(await page.getByRole("button", { name: "Download public key" }).count(), 0);
    assert.equal(await page.getByRole("button", { name: "Download encrypted private key" }).count(), 0);
    await checkServerRecipientGuard(page, publicKeyPath, fingerprint);

    await page.getByRole("button", { name: "Encrypt" }).first().click();
    await page.getByRole("heading", { name: "Encrypt a file" }).waitFor();
    await page.getByLabel("File to encrypt").setInputFiles(inputPath);
    await page.getByLabel("Recipient public key").setInputFiles(publicKeyPath);
    await page.getByText("Compatible public key", { exact: true }).waitFor({ state: "visible" });
    await selectExpectedRecipient(page, fingerprint, "Encrypt file");
    await capture(page, "custom-web-encrypt-workflow.png");
    const encryptedDownload = page.waitForEvent("download");
    await page.getByRole("button", { name: "Encrypt file" }).click();
    await saveDownload(await encryptedDownload, encryptedPath);
    await page.getByText("File encrypted", { exact: true }).waitFor({ state: "visible" });

    await decryptFromUi(page, encryptedPath, privateKeyPath, decryptedPath);
    assert.deepEqual(await readFile(decryptedPath), inputBytes, "The native browser round trip returned different bytes.");

    await runBatchRoundTrips(page, temporaryDirectory, publicKeyPath, privateKeyPath, fingerprint);
    await runPasswordChange(page, temporaryDirectory, privateKeyPath, encryptedPath);
    await runPublicKeyRecovery(page, temporaryDirectory, publicKeyPath, privateKeyPath);
    await runFileVerification(page, temporaryDirectory, privateKeyPath, encryptedPath);
    assert.equal(health.largeFiles?.available, true, "Large-file jobs must be available for the native browser checks.");
    await runLargeFileRoundTrip(page, temporaryDirectory, publicKeyPath, privateKeyPath, fingerprint);
    const encryptionRequests = await page.evaluate(() => window.recipientChecks);
    assert.deepEqual(encryptionRequests.filter(({ pathname }) => pathname === "/api/files/encrypt")
      .map(({ expected }) => expected), [[fingerprint], [fingerprint], [fingerprint]],
      "Single-file and both batch requests must carry exactly one expected recipient.");
    assert.deepEqual(encryptionRequests.filter(({ pathname }) => pathname.endsWith("/start"))
      .map(({ expected }) => expected), [[fingerprint], [], []],
      "Only the encrypt-mode large-file start must carry the expected recipient.");
    await page.getByRole("button", { name: "Inspect key", exact: true }).click();
    await page.getByRole("heading", { name: "Inspect a key", exact: true }).waitFor();
    await page.getByLabel("Key file", { exact: true }).setInputFiles(publicKeyPath);
    await page.getByRole("region", { name: "Key inspection result" }).waitFor();
    await page.getByRole("main").getByText("Technical details", { exact: true }).click();
    await page.setViewportSize({ width: 390, height: 844 });
    await capture(page, "custom-web-mobile-inspect.png");
    console.log("Native browser recipient verification, encryption/decryption, key password change, public-key recovery, verification, and large-file checks passed.");
  } finally {
    try {
      await browser?.close();
    } finally {
      if (temporaryDirectory) await rm(temporaryDirectory, { recursive: true, force: true });
    }
  }
}

try {
  await run();
} catch {
  console.error("Native browser encryption, decryption, key recovery/password change, or file verification check failed.");
  process.exitCode = 1;
}
