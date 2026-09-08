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
    console.log("Native browser single-file, batch encryption/decryption, and private-key password-change round trips passed.");
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
  console.error("Native browser encryption, decryption, or key password-change round trip failed.");
  process.exitCode = 1;
}
