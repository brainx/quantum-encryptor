import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { chromium } from "playwright";

const baseUrl = process.env.UI_NATIVE_URL ?? "http://127.0.0.1:4000/";
const password = "correct horse battery staple";
const updatedPassword = "new correct horse battery staple";
const inputBytes = Buffer.from("native browser round trip");

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

async function runBatchRoundTrips(page, temporaryDirectory, publicKeyPath, privateKeyPath) {
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

async function run() {
  let temporaryDirectory;
  let browser;

  try {
    temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "quantum-encryptor-native-ui-"));
    const inputPath = path.join(temporaryDirectory, "input.txt");
    const publicKeyPath = path.join(temporaryDirectory, "public.pem");
    const privateKeyPath = path.join(temporaryDirectory, "private.pem");
    const encryptedPath = path.join(temporaryDirectory, "input_encrypted.pqc");
    const decryptedPath = path.join(temporaryDirectory, "input_decrypted.txt");
    await writeFile(inputPath, inputBytes);

    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();

    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await page.getByRole("heading", { name: "Encrypt a file" }).waitFor();

    const health = await page.evaluate(async () => {
      const response = await fetch("/api/health", { credentials: "same-origin" });
      if (!response.ok) return null;
      return response.json();
    });
    assertReadyHealth(health);
    await page.getByText("Ready", { exact: true }).first().waitFor({ state: "visible" });

    await page.getByRole("button", { name: "Generate keys" }).click();
    await page.getByRole("heading", { name: "Generate keys" }).waitFor();
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    await page.getByLabel("Confirm private key password").fill(password);
    await page.getByRole("button", { name: "Generate key pair" }).click();
    await page.getByText("Key pair generated", { exact: true }).waitFor({ state: "visible" });
    await downloadFromButton(page, "Download public key", publicKeyPath);
    await downloadFromButton(page, "Download encrypted private key", privateKeyPath);
    await page.getByRole("button", { name: "Clear generated keys" }).click();
    assert.equal(await page.getByRole("button", { name: "Download public key" }).count(), 0);
    assert.equal(await page.getByRole("button", { name: "Download encrypted private key" }).count(), 0);

    await page.getByRole("button", { name: "Encrypt" }).first().click();
    await page.getByRole("heading", { name: "Encrypt a file" }).waitFor();
    await page.getByLabel("File to encrypt").setInputFiles(inputPath);
    await page.getByLabel("Recipient public key").setInputFiles(publicKeyPath);
    await page.getByText("Compatible public key", { exact: true }).waitFor({ state: "visible" });
    const encryptedDownload = page.waitForEvent("download");
    await page.getByRole("button", { name: "Encrypt file" }).click();
    await saveDownload(await encryptedDownload, encryptedPath);
    await page.getByText("File encrypted", { exact: true }).waitFor({ state: "visible" });

    await decryptFromUi(page, encryptedPath, privateKeyPath, decryptedPath);
    assert.deepEqual(await readFile(decryptedPath), inputBytes, "The native browser round trip returned different bytes.");

    await runBatchRoundTrips(page, temporaryDirectory, publicKeyPath, privateKeyPath);
    await runPasswordChange(page, temporaryDirectory, privateKeyPath, encryptedPath);
    await runPublicKeyRecovery(page, temporaryDirectory, publicKeyPath, privateKeyPath);
    await runFileVerification(page, temporaryDirectory, privateKeyPath, encryptedPath);
    console.log("Native browser encryption/decryption, key password change, public-key recovery, and file verification checks passed.");
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
