import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import AxeBuilder from "@axe-core/playwright";
import { chromium } from "playwright";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(rootDir, "tmp", "ui-smoke");
const baseUrl = process.env.UI_SMOKE_URL ?? "http://127.0.0.1:4000/";

const publicInspection = {
  ok: true,
  keyInfo: { kem: "ML-KEM-768+X25519-v2", key_type: "public" },
  display: {
    "Key Type": "Public key",
    "Hybrid suite": "ML-KEM-768+X25519-v2"
  }
};

const outdatedPublicInspection = {
  ok: true,
  keyInfo: { kem: "ML-KEM-768+X25519", key_type: "public" },
  display: {
    "Key Type": "Public key",
    "Hybrid suite": "ML-KEM-768+X25519"
  }
};

const privateInspection = {
  ok: true,
  keyInfo: {
    kem: "ML-KEM-768+X25519-v2",
    key_type: "private",
    private_key_encrypted: true,
    private_key_format_version: 2,
    private_key_kdf: "scrypt"
  },
  display: {
    "Key Type": "Encrypted private key",
    "Key format": "2",
    "Key KDF": "scrypt",
    "Hybrid suite": "ML-KEM-768+X25519-v2"
  }
};

function health({ limited = false, strictFileLimit = false } = {}) {
  const available = { available: true, reason: "" };
  return {
    ok: true,
    backendReady: !limited,
    backendMessage: limited
      ? "The ML-KEM backend is not ready, so new keys and ciphertexts cannot be created. Compatible encrypted archives may still be decryptable."
      : "Post-quantum backend ready.",
    capabilities: limited
      ? {
          inspect: available,
          generate: { available: false, reason: "Key generation is unavailable in this local engine." },
          encrypt: { available: false, reason: "Encryption is unavailable in this local engine." },
          decrypt: available
        }
      : { inspect: available, generate: available, encrypt: available, decrypt: available },
    formatVersion: 4,
    kem: "ML-KEM-768+X25519-v2",
    kemComponent: "ML-KEM-768",
    configuredKem: "ML-KEM-768",
    dem: "AES-256-GCM",
    maxFileBytes: strictFileLimit ? 3 : 104857600,
    maxEncryptedFileBytes: 105906314,
    maxPemBytes: 131072,
    passwordPolicy: { minChars: 16, minUniqueChars: 5 }
  };
}

function json(route, payload, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(payload)
  });
}

function errorPayload(errorCode, message) {
  return { ok: false, error_code: errorCode, message };
}

function file(name, contents, mimeType = "application/octet-stream") {
  return { name, mimeType, buffer: Buffer.from(contents) };
}

function activeElementLabel() {
  const element = document.activeElement;
  if (!(element instanceof HTMLElement)) return "";
  const associatedLabel = "labels" in element && element.labels?.[0]?.textContent?.trim();
  return element.getAttribute("aria-label") || associatedLabel || element.textContent?.trim() || element.id;
}

async function collectTabOrder(page, limit = 40) {
  await page.evaluate(() => (document.activeElement instanceof HTMLElement ? document.activeElement.blur() : undefined));
  const order = [];
  for (let index = 0; index < limit; index += 1) {
    await page.keyboard.press("Tab");
    order.push(await page.evaluate(activeElementLabel));
  }
  return order;
}

function assertLogicalTabOrder(order, labels) {
  let lastIndex = -1;
  for (const label of labels) {
    const nextIndex = order.findIndex((value, index) => index > lastIndex && value === label);
    assert.notEqual(nextIndex, -1, `Tab did not reach ${label}: ${JSON.stringify(order)}`);
    lastIndex = nextIndex;
  }
}

async function assertNoHorizontalOverflow(page) {
  for (const viewport of [
    { width: 390, height: 844 },
    { width: 768, height: 900 },
    { width: 1024, height: 768 },
    { width: 1440, height: 900 }
  ]) {
    await page.setViewportSize(viewport);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
    assert.equal(overflow, false, `horizontal overflow at ${viewport.width}`);
  }
}

async function assertAxe(page, label) {
  const scan = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  assert.deepEqual(scan.violations, [], `${label} accessibility violations: ${JSON.stringify(scan.violations, null, 2)}`);
}

await mkdir(outDir, { recursive: true });

let limitedHealth = false;
let strictFileLimit = false;
const unexpectedApiRequests = [];
const apiRequests = [];
let staleInspectionRoute = null;
let captureStaleInspectionRoute;
const staleInspectionRouteCaptured = new Promise((resolve) => {
  captureStaleInspectionRoute = resolve;
});
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const method = request.method();
    const payload = request.postDataBuffer()?.toString("utf8") ?? "";
    apiRequests.push(`${method} ${pathname}`);

    if (method === "GET" && pathname === "/api/health") {
      return json(route, health({ limited: limitedHealth, strictFileLimit }));
    }
    if (method === "POST" && pathname === "/api/keys/inspect") {
      if (payload.includes("stale-first.pem")) {
        staleInspectionRoute = route;
        captureStaleInspectionRoute();
        return;
      }
      if (payload.includes("outdated-public.pem")) return json(route, outdatedPublicInspection);
      if (payload.includes("wrong-key-type.pem")) return json(route, privateInspection);
      return json(route, payload.includes("private.pem") ? privateInspection : publicInspection);
    }
    if (method === "POST" && pathname === "/api/keys/generate") {
      return json(route, {
        ok: true,
        kem: "ML-KEM-768+X25519-v2",
        publicPem: "PUBLIC-PEM",
        privatePem: "PRIVATE-PEM",
        publicFilename: "quantum_public.pem",
        privateFilename: "quantum_private_encrypted.pem"
      });
    }
    if (method === "POST" && pathname === "/api/files/encrypt") {
      if (payload.includes("unexpected-backend-error.txt")) {
        return json(route, errorPayload("unexpected_backend_error", "Raw fixture detail: /not-for-the-user"), 500);
      }
      return route.fulfill({
        status: 200,
        contentType: "application/octet-stream",
        headers: { "Content-Disposition": 'attachment; filename="report_encrypted.pqc"' },
        body: "ciphertext"
      });
    }
    if (method === "POST" && pathname === "/api/files/decrypt") {
      if (payload.includes("tampered_encrypted.pqc")) {
        return json(route, errorPayload("decryption_failed", "Ciphertext authentication failed."), 422);
      }
      return route.fulfill({
        status: 200,
        contentType: "application/octet-stream",
        headers: { "Content-Disposition": 'attachment; filename="report.txt"' },
        body: "plaintext"
      });
    }
    unexpectedApiRequests.push(`${method} ${pathname}`);
    return json(route, errorPayload("unexpected_ui_smoke_api_request", "Unexpected local test API request."), 500);
  });

  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "Encrypt a file" }).waitFor();
  assert.equal(await page.getByRole("main").count(), 1);
  assert.equal(await page.getByRole("navigation", { name: "Workflows" }).count(), 1);
  assert.equal(await page.getByRole("button", { name: "Encrypt" }).first().getAttribute("aria-current"), "page");
  await expectText(page, "Ready");

  strictFileLimit = true;
  await page.reload({ waitUntil: "networkidle" });
  const encryptRequestsBeforeOversizedFile = apiRequests.filter((request) => request === "POST /api/files/encrypt").length;
  await page.getByLabel("File to encrypt").setInputFiles(file("oversized.txt", "four", "text/plain"));
  await expectText(page, "This file exceeds the 3 byte limit.");
  assert.equal(await page.getByRole("button", { name: "Encrypt file" }).isDisabled(), true);
  assert.equal(
    apiRequests.filter((request) => request === "POST /api/files/encrypt").length,
    encryptRequestsBeforeOversizedFile,
    "oversized files must not trigger encryption requests"
  );

  strictFileLimit = false;
  await page.reload({ waitUntil: "networkidle" });

  await page.getByLabel("File to encrypt").setInputFiles(file("report.txt", "local report", "text/plain"));
  await page.getByLabel("Recipient public key").setInputFiles(file("public.pem", "PUBLIC-PEM", "application/x-pem-file"));
  await expectText(page, "Compatible public key");
  await page.getByRole("button", { name: "Encrypt file" }).waitFor({ state: "visible" });
  assert.equal(await page.getByRole("button", { name: "Encrypt file" }).isEnabled(), true);
  assert.equal(await page.getByLabel("Output filename").inputValue(), "report_encrypted.pqc");

  const desktopTabOrder = await collectTabOrder(page);
  assertLogicalTabOrder(desktopTabOrder, ["Encrypt", "File to encrypt", "Recipient public key", "Output filename", "Encrypt file", "Technical details"]);
  assert.equal(await page.getByText("Technical details").first().evaluate((element) => element.parentElement?.open), false);
  await page.getByText("Technical details").first().click();
  assert.equal(await page.getByText("Technical details").first().evaluate((element) => element.parentElement?.open), true);
  await assertNoHorizontalOverflow(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await assertAxe(page, "ready Encrypt screen");
  await page.screenshot({ path: path.join(outDir, "quantum-encryptor-web.png"), fullPage: true });

  await page.getByRole("button", { name: "Encrypt file" }).click();
  await expectText(page, "File encrypted");
  await expectText(page, "Saved report_encrypted.pqc.");

  await page.getByLabel("Recipient public key").setInputFiles(file("outdated-public.pem", "OUTDATED", "application/x-pem-file"));
  await expectText(page, "This public key uses ML-KEM-768+X25519; encryption requires ML-KEM-768+X25519-v2.");
  assert.equal(await page.getByRole("button", { name: "Encrypt file" }).isDisabled(), true);

  await page.getByLabel("Recipient public key").setInputFiles(file("wrong-key-type.pem", "PRIVATE-PEM", "application/x-pem-file"));
  await expectText(page, "Private key — not valid for encryption");
  assert.equal(await page.getByRole("button", { name: "Encrypt file" }).isDisabled(), true);

  await page.getByLabel("Recipient public key").setInputFiles(file("public.pem", "PUBLIC-PEM", "application/x-pem-file"));
  await expectText(page, "Compatible public key");
  await page.getByLabel("File to encrypt").setInputFiles(file("unexpected-backend-error.txt", "safe local fixture", "text/plain"));
  await page.getByRole("button", { name: "Encrypt file" }).click();
  await expectText(page, "Could not encrypt this file. Confirm the recipient key and try again.");
  assert.equal(await page.getByText("Raw fixture detail: /not-for-the-user").count(), 0);

  await page.getByRole("button", { name: "Inspect key" }).first().click();
  await page.getByRole("heading", { name: "Inspect a key" }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Inspect key" }).first().getAttribute("aria-current"), "page");
  await page.getByLabel("Key file").setInputFiles(file("public.pem", "PUBLIC-PEM", "application/x-pem-file"));
  await expectText(page, "Public key");
  await page.getByText("Technical details").first().click();
  await expectText(page, "ML-KEM-768+X25519-v2");
  await page.getByLabel("Key file").setInputFiles(file("private.pem", "PRIVATE-PEM", "application/x-pem-file"));
  await expectText(page, "Encrypted private key");
  await page.getByText("Technical details").first().click();
  await expectText(page, "scrypt");
  await page.getByLabel("Key file").setInputFiles(file("stale-first.pem", "STALE", "application/x-pem-file"));
  await staleInspectionRouteCaptured;
  await page.getByLabel("Key file").setInputFiles(file("public.pem", "PUBLIC-PEM", "application/x-pem-file"));
  await expectText(page, "Public key");
  await staleInspectionRoute?.abort("failed");
  assert.equal(await page.getByText("Public key").count() > 0, true, "replaced inspection must remain current after cancellation");

  await page.getByRole("button", { name: "Generate keys" }).click();
  await page.getByRole("heading", { name: "Generate keys" }).waitFor();
  await page.getByLabel("Private key password", { exact: true }).fill("correct-horse-battery-staple");
  await page.getByLabel("Confirm private key password").fill("correct-horse-battery-staple");
  await page.getByRole("button", { name: "Generate key pair" }).click();
  await expectText(page, "Key pair generated");
  await expectText(page, "quantum_public.pem");
  await expectText(page, "quantum_private_encrypted.pem");
  await page.getByRole("button", { name: "Clear generated keys" }).click();
  assert.equal(await page.getByRole("button", { name: "Download public key" }).count(), 0);
  assert.equal(await page.getByRole("button", { name: "Download encrypted private key" }).count(), 0);

  await page.getByRole("button", { name: "Decrypt" }).first().click();
  await page.getByRole("heading", { name: "Decrypt a file" }).waitFor();
  await page.getByLabel("Encrypted file").setInputFiles(file("report_encrypted.pqc", "ciphertext"));
  await page.getByLabel("Private key", { exact: true }).setInputFiles(file("private.pem", "PRIVATE-PEM", "application/x-pem-file"));
  await expectText(page, "Supported encrypted private key; match not yet verified");
  await page.getByLabel("Private key password", { exact: true }).fill("correct-horse-battery-staple");
  assert.equal(await page.getByLabel("Output filename").inputValue(), "report");
  await page.getByRole("button", { name: "Decrypt file" }).click();
  await expectText(page, "File decrypted");
  await expectText(page, "Saved report.txt.");

  await page.getByLabel("Encrypted file").setInputFiles(file("tampered_encrypted.pqc", "tampered"));
  await page.getByLabel("Private key password", { exact: true }).fill("correct-horse-battery-staple");
  await page.getByRole("button", { name: "Decrypt file" }).click();
  await expectText(page, "Decryption failed");
  await expectText(page, "The file could not be authenticated. Check the encrypted file, private key, and password.");
  assert.equal(await page.getByText("Ciphertext authentication failed.").count(), 0);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("link", { name: "Inspect key" }).click();
  await page.getByRole("heading", { name: "Inspect a key" }).waitFor();
  assert.equal(await page.getByRole("link", { name: "Inspect key" }).getAttribute("aria-current"), "page");
  await page.getByLabel("Key file").setInputFiles(file("public.pem", "PUBLIC-PEM", "application/x-pem-file"));
  await expectText(page, "Public key");
  await assertAxe(page, "mobile Inspect screen");
  await page.screenshot({ path: path.join(outDir, "quantum-encryptor-mobile.png"), fullPage: true });

  await page.emulateMedia({ reducedMotion: "reduce" });
  const reducedMotionDuration = await page.locator(".app-mobile-navigation a").first().evaluate(
    (element) => getComputedStyle(element).transitionDuration
  );
  assert.ok(
    reducedMotionDuration.split(", ").every((duration) => Number.parseFloat(duration) <= 0.01),
    `reduced-motion transition duration is too long: ${reducedMotionDuration}`
  );

  limitedHealth = true;
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.reload({ waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "Encrypt a file" }).waitFor();
  await expectText(page, "Limited");
  await expectText(page, "Encryption is unavailable in this local engine.");
  assert.equal(await page.getByLabel("File to encrypt").count(), 0);
  await page.getByText("Capability details").first().click();
  await expectText(page, "Key generation is unavailable in this local engine.");
  await expectText(page, "Encryption is unavailable in this local engine.");

  await page.getByRole("button", { name: "Inspect key" }).first().click();
  await page.getByRole("heading", { name: "Inspect a key" }).waitFor();
  assert.equal(await page.getByLabel("Key file").count(), 1);

  await page.getByRole("button", { name: "Generate keys" }).click();
  await page.getByRole("heading", { name: "Generate keys" }).waitFor();
  await expectText(page, "Key generation is unavailable in this local engine.");
  assert.equal(await page.getByLabel("Private key password", { exact: true }).count(), 0);
  assert.equal(await page.getByRole("button", { name: "Generate key pair" }).count(), 0);

  await page.getByRole("button", { name: "Encrypt" }).first().click();
  await page.getByRole("heading", { name: "Encrypt a file" }).waitFor();
  await expectText(page, "Encryption is unavailable in this local engine.");
  assert.equal(await page.getByLabel("File to encrypt").count(), 0);

  await page.getByRole("button", { name: "Decrypt" }).first().click();
  await page.getByRole("heading", { name: "Decrypt a file" }).waitFor();
  assert.equal(await page.getByRole("button", { name: "Decrypt file" }).isDisabled(), true);
  await expectText(page, "Choose an encrypted file.");

  assert.deepEqual(unexpectedApiRequests, [], `Unexpected API requests: ${unexpectedApiRequests.join(", ")}`);

  console.log(JSON.stringify({
    health: ["all capabilities", "inspect and decrypt"],
    workflows: ["inspect", "generate", "encrypt", "decrypt", "decryption_failed"],
    viewports: [390, 768, 1024, 1440],
    screenshots: ["quantum-encryptor-web.png", "quantum-encryptor-mobile.png"]
  }, null, 2));
} finally {
  await browser.close();
}

async function expectText(page, text) {
  await page.getByText(text, { exact: true }).filter({ visible: true }).first().waitFor({ state: "visible" });
}
