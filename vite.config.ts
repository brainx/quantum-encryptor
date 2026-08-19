/// <reference types="vitest/config" />

import { defineConfig, loadEnv, type UserConfig } from "vite";
import react from "@vitejs/plugin-react";

type ViteEnvironment = {
  PORT?: string;
  QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV?: string;
};

function configuredPort(value: string | undefined): number {
  if (value === undefined) {
    return 4000;
  }

  const port = Number(value);
  if (!/^[0-9]+$/.test(value) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT must be an integer from 1 through 65535.");
  }
  return port;
}

export function loadViteEnvironment(mode: string): ViteEnvironment {
  const loaded = loadEnv(mode, ".", ["PORT", "QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV"]);
  return {
    PORT: loaded.PORT,
    QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV: loaded.QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV
  };
}

export function createViteConfig(environment: ViteEnvironment): UserConfig {
  const port = configuredPort(environment.PORT);
  return {
    root: "web",
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: 4001,
      strictPort: true,
      proxy:
        environment.QUANTUM_ENCRYPTOR_ENABLE_VITE_DEV === "1"
          ? {
              "/api": {
                target: `http://127.0.0.1:${port}`,
                changeOrigin: false
              }
            }
          : undefined
    },
    build: {
      outDir: "../static/app",
      emptyOutDir: true
    },
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      clearMocks: true,
      restoreMocks: true
    }
  };
}

export default defineConfig(({ mode }) => createViteConfig(loadViteEnvironment(mode)));
