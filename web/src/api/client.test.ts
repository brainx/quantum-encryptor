import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { READY_HEALTH } from "../test/fixtures";

const fingerprint = `QE1-SHA3-256:${"a".repeat(64)}`;
const json = (payload: unknown, status = 200) => new Response(JSON.stringify(payload), { status });
const file = new File(["file"], "file.txt");
const key = new File(["PEM"], "public.pem");
const unsupportedError = {
  status: 409, code: "recipient_fingerprint_unsupported",
  message: "Restart an updated local service to enforce the expected recipient fingerprint."
};
beforeEach(() => vi.resetModules());
afterEach(() => vi.unstubAllGlobals());

describe("recipient fingerprint encryption requests", () => {
  it.each([undefined, false])("does not send protected encryption to a service without fresh support (%s)", async (supportsRecipientFingerprint) => {
    const fetch = vi.fn().mockImplementation((url: string) => Promise.resolve(url === "/api/health"
      ? json({ ...READY_HEALTH, supportsRecipientFingerprint }) : new Response("ciphertext")));
    vi.stubGlobal("fetch", fetch);
    const { encryptFile } = await import("./client");
    await expect(encryptFile(file, key, "file.pqc", undefined, fingerprint)).rejects.toMatchObject(unsupportedError);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(["/api/health"]);
  });

  it("rechecks support for a protected request after the authentication cookie was already bootstrapped", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json(READY_HEALTH))
      .mockResolvedValueOnce(new Response("unprotected ciphertext"))
      .mockResolvedValueOnce(json({ ...READY_HEALTH, supportsRecipientFingerprint: false }));
    vi.stubGlobal("fetch", fetch);
    const { encryptFile } = await import("./client");
    await encryptFile(file, key, "file.pqc");
    await expect(encryptFile(file, key, "file.pqc", undefined, fingerprint)).rejects.toMatchObject(unsupportedError);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(["/api/health", "/api/files/encrypt", "/api/health"]);
  });

  it("does not retry protected encryption when a restarted service loses support", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json(READY_HEALTH))
      .mockResolvedValueOnce(json({ error_code: "missing_api_token" }, 403))
      .mockResolvedValueOnce(json({ ...READY_HEALTH, supportsRecipientFingerprint: undefined }))
      .mockResolvedValueOnce(new Response("unsafe ciphertext"));
    vi.stubGlobal("fetch", fetch);
    const { encryptFile } = await import("./client");
    await expect(encryptFile(file, key, "file.pqc", undefined, fingerprint)).rejects.toMatchObject(unsupportedError);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(["/api/health", "/api/files/encrypt", "/api/health"]);
  });

  it("retries authentication once only when the refreshed service still enforces fingerprints", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(json(READY_HEALTH))
      .mockResolvedValueOnce(json({ error_code: "missing_api_token" }, 403))
      .mockResolvedValueOnce(json(READY_HEALTH)).mockResolvedValueOnce(new Response("ciphertext"));
    vi.stubGlobal("fetch", fetch);
    const { encryptFile } = await import("./client");
    const signal = new AbortController().signal;
    await encryptFile(file, key, "file.pqc", signal, fingerprint);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(["/api/health", "/api/files/encrypt", "/api/health", "/api/files/encrypt"]);
    const posts = fetch.mock.calls.filter(([url]) => url === "/api/files/encrypt");
    for (const [, request] of posts) {
      expect(request.signal).toBe(signal);
      expect(request.body.get("expected_recipient_fingerprint")).toBe(fingerprint);
    }
  });

  it.each([false, true])("does not post after cancellation during a support refresh (retry=%s)", async (retry) => {
    let resolveHealth!: (response: Response) => void;
    const health = new Promise<Response>((resolve) => { resolveHealth = resolve; });
    const fetch = vi.fn();
    if (retry) fetch.mockResolvedValueOnce(json(READY_HEALTH)).mockResolvedValueOnce(json({ error_code: "missing_api_token" }, 403));
    fetch.mockReturnValueOnce(health).mockResolvedValue(new Response("must not encrypt"));
    vi.stubGlobal("fetch", fetch);
    const { encryptFile } = await import("./client");
    const controller = new AbortController();
    const pending = encryptFile(file, key, "file.pqc", controller.signal, fingerprint);
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(retry ? 3 : 1));
    controller.abort();
    resolveHealth(json(READY_HEALTH));
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(fetch.mock.calls.filter(([url]) => url === "/api/files/encrypt")).toHaveLength(retry ? 1 : 0);
  });

  it.each([undefined, fingerprint, ""])("preserves an explicitly supplied expectation and omits only undefined (%s)", async (expected) => {
    const fetch = vi.fn().mockImplementation((url: string) => Promise.resolve(url === "/api/health"
      ? new Response(JSON.stringify(READY_HEALTH)) : new Response("ciphertext")));
    vi.stubGlobal("fetch", fetch);
    const { encryptFile } = await import("./client");
    const signal = new AbortController().signal;
    await encryptFile(new File(["file"], "file.txt"), new File(["PEM"], "public.pem"), "file.pqc", signal, expected);
    const [, request] = fetch.mock.calls.find(([url]) => url === "/api/files/encrypt")!;
    expect(request.method).toBe("POST");
    expect(request.signal).toBe(signal);
    expect(request.body.get("expected_recipient_fingerprint")).toBe(expected ?? null);
    expect(request.body.get("output_filename")).toBe("file.pqc");
  });

  it.each(["invalid_recipient_fingerprint", "recipient_fingerprint_mismatch"])("does not retry a rejected fingerprint (%s)", async (code) => {
    const fetch = vi.fn().mockImplementation((url: string) => Promise.resolve(url === "/api/health"
      ? new Response(JSON.stringify(READY_HEALTH))
      : new Response(JSON.stringify({ error_code: code, message: "Check the expected fingerprint." }), { status: 400 })));
    vi.stubGlobal("fetch", fetch);
    const { encryptFile } = await import("./client");
    await expect(encryptFile(new File(["a"], "a"), new File(["PEM"], "key.pem"), "a.pqc", undefined, fingerprint))
      .rejects.toMatchObject({ status: 400, code, message: "Check the expected fingerprint." });
    expect(fetch.mock.calls.filter(([url]) => url === "/api/files/encrypt")).toHaveLength(1);
  });
});
