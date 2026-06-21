import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(rootDir, "tmp", "ui-smoke");
const baseUrl = process.env.UI_SMOKE_URL ?? "http://127.0.0.1:4000/";

await mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  const states = {
    encryptDisabled: await page.getByRole("button", { name: "Encrypt File" }).last().isDisabled()
  };

  await page.getByRole("button", { name: "Decrypt File" }).click();
  states.decryptVisible = await page.getByRole("heading", { name: "Decrypt File" }).isVisible();
  states.decryptDisabled = await page.getByRole("button", { name: "Decrypt File" }).last().isDisabled();

  await page.getByRole("button", { name: "Generate Keys" }).click();
  states.generateVisible = await page.getByRole("heading", { name: "Generate Keys" }).isVisible();
  states.generateDisabled = await page.getByRole("button", { name: /Generate .* Key Pair/ }).isDisabled();

  await page.getByRole("button", { name: "Inspect Key" }).click();
  states.inspectVisible = await page.getByRole("heading", { name: "Inspect Key" }).isVisible();

  await page.setViewportSize({ width: 1280, height: 720 });
  await page.getByRole("button", { name: "Encrypt File" }).click();
  await page.screenshot({ path: path.join(outDir, "quantum-encryptor-web.png"), fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Inspect Key" }).click();
  await page.screenshot({ path: path.join(outDir, "quantum-encryptor-mobile.png"), fullPage: true });

  if (!states.encryptDisabled || !states.decryptVisible || !states.decryptDisabled) {
    throw new Error(`Unexpected file workflow state: ${JSON.stringify(states)}`);
  }
  if (!states.generateVisible || !states.generateDisabled || !states.inspectVisible) {
    throw new Error(`Unexpected key workflow state: ${JSON.stringify(states)}`);
  }

  console.log(JSON.stringify(states, null, 2));
} finally {
  await browser.close();
}
