import { describe, expect, it } from "vitest";
import { createViteConfig } from "../../vite.config";

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
});
