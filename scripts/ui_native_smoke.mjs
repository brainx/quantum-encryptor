import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { chromium } from "playwright";

const baseUrl = process.env.UI_NATIVE_URL ?? "http://127.0.0.1:4000/";
const password = "correct horse battery staple";
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
  await page.getByRole("button", { name }).click();
  return saveDownload(await downloadPromise, destination);
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

    await page.getByRole("button", { name: "Decrypt" }).first().click();
    await page.getByRole("heading", { name: "Decrypt a file" }).waitFor();
    await page.getByLabel("Encrypted file").setInputFiles(encryptedPath);
    await page.getByLabel("Private key", { exact: true }).setInputFiles(privateKeyPath);
    await page
      .getByText("Supported encrypted private key; match not yet verified", { exact: true })
      .waitFor({ state: "visible" });
    await page.getByLabel("Private key password", { exact: true }).fill(password);
    const decryptedDownload = page.waitForEvent("download");
    await page.getByRole("button", { name: "Decrypt file" }).click();
    await saveDownload(await decryptedDownload, decryptedPath);
    await page.getByText("File decrypted", { exact: true }).waitFor({ state: "visible" });

    assert.deepEqual(await readFile(decryptedPath), inputBytes, "The native browser round trip returned different bytes.");
    console.log("Native browser encryption round trip passed.");
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
  console.error("Native browser encryption round trip failed.");
  process.exitCode = 1;
}
