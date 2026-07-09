import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { transformWithOxc } from "vite";

let moduleSequence = 0;

async function loadApiModule() {
  const source = await readFile(new URL("../web/src/api.ts", import.meta.url), "utf8");
  const compiled = (
    await transformWithOxc(source, "api.ts", {
      lang: "ts",
      sourcemap: false
    })
  ).code;
  const encoded = Buffer.from(compiled).toString("base64");
  moduleSequence += 1;
  return import(`data:text/javascript;base64,${encoded}#${moduleSequence}`);
}

function healthPayload(apiToken) {
  return {
    ok: true,
    backendReady: true,
    backendMessage: "Post-quantum backend ready.",
    formatVersion: 3,
    kem: "ML-KEM-768",
    configuredKem: "ML-KEM-768",
    dem: "AES-256-GCM",
    maxFileBytes: 104857600,
    maxEncryptedFileBytes: 104989748,
    maxPemBytes: 131072,
    apiToken,
    passwordPolicy: {
      minChars: 16,
      minUniqueChars: 5
    }
  };
}

function generatedKeysPayload() {
  return {
    ok: true,
    kem: "ML-KEM-768",
    publicPem: "PUBLIC PEM",
    privatePem: "PRIVATE PEM",
    publicFilename: "quantum_public_key.pem",
    privateFilename: "quantum_private_key.pem"
  };
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

test("a token rejection refreshes health and retries the state-changing request once", async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const calls = [];
  let healthRequests = 0;
  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    const token = new Headers(init.headers).get("X-Quantum-Encryptor-Token");
    calls.push({ url, token });

    if (url === "/api/health") {
      healthRequests += 1;
      return jsonResponse(healthPayload(healthRequests === 1 ? "stale-token" : "fresh-token"));
    }
    if (url === "/api/keys/generate" && token === "stale-token") {
      return jsonResponse(
        { ok: false, error_code: "missing_api_token", message: "Local API token is invalid." },
        403
      );
    }
    if (url === "/api/keys/generate" && token === "fresh-token") {
      return jsonResponse(generatedKeysPayload());
    }
    throw new Error(`Unexpected request: ${url} (${token})`);
  };

  const api = await loadApiModule();
  const result = await api.generateKeys("correct horse battery staple");

  assert.equal(result.publicFilename, "quantum_public_key.pem");
  assert.deepEqual(calls, [
    { url: "/api/health", token: null },
    { url: "/api/keys/generate", token: "stale-token" },
    { url: "/api/health", token: null },
    { url: "/api/keys/generate", token: "fresh-token" }
  ]);
});

test("an unrelated authorization rejection is not retried", async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    const token = new Headers(init.headers).get("X-Quantum-Encryptor-Token");
    calls.push({ url, token });
    if (url === "/api/health") return jsonResponse(healthPayload("current-token"));
    if (url === "/api/keys/generate") {
      return jsonResponse({ ok: false, error_code: "origin_forbidden", message: "Origin is not allowed." }, 403);
    }
    throw new Error(`Unexpected request: ${url} (${token})`);
  };

  const api = await loadApiModule();

  await assert.rejects(
    api.generateKeys("correct horse battery staple"),
    (error) => error instanceof api.ApiError && error.code === "origin_forbidden"
  );
  assert.deepEqual(calls, [
    { url: "/api/health", token: null },
    { url: "/api/keys/generate", token: "current-token" }
  ]);
});
