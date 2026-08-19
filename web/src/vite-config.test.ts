import { afterEach, describe, expect, it, vi } from "vitest";
import { createViteConfig, loadViteEnvironment } from "../../vite.config";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("createViteConfig", () => {
  it("does not proxy API requests without the explicit Vite opt-in", () => {
    expect(createViteConfig({}).server?.proxy).toBeUndefined();
  });

  it("uses the configured API port while preserving the browser host when enabled", () => {
    expect(
      createViteConfig({
        PORT: "4020",
        QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV: "1"
      }).server?.proxy
    ).toEqual({
      "/api": {
        target: "http://127.0.0.1:4020",
        changeOrigin: false
      }
    });
  });

  it("requires the exact opt-in value", () => {
    expect(createViteConfig({ QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV: "true" }).server?.proxy).toBeUndefined();
  });

  it("defaults an unset API port to 4000", () => {
    expect(createViteConfig({ QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV: "1" }).server?.proxy).toEqual({
      "/api": {
        target: "http://127.0.0.1:4000",
        changeOrigin: false
      }
    });
  });

  it.each(["", "0", "65536", "abc", " 4000 "])("rejects invalid API port %j", (port) => {
    expect(() => createViteConfig({ PORT: port })).toThrow("PORT must be an integer from 1 through 65535.");
  });
});

describe("loadViteEnvironment", () => {
  it("selects only the exact Vite settings at the environment-loading boundary", () => {
    const sentinel = "test-token-must-not-enter-vite-config";
    vi.stubEnv("PORT", "4020");
    vi.stubEnv("QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV", "1");
    vi.stubEnv("QUANTUM_ENCRYPTOR_API_TOKEN", sentinel);

    const environment = loadViteEnvironment("test");
    const config = createViteConfig(environment);

    expect(environment).toEqual({
      PORT: "4020",
      QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV: "1"
    });
    expect(environment).not.toHaveProperty("QUANTUM_ENCRYPTOR_API_TOKEN");
    expect(JSON.stringify(config)).not.toContain(sentinel);
  });
});
