/// <reference types="vitest/config" />

import { defineConfig, loadEnv, type UserConfig } from "vite";
import react from "@vitejs/plugin-react";

export function createViteConfig(environment: Record<string, string | undefined>): UserConfig {
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
                target: `http://127.0.0.1:${environment.PORT ?? "4000"}`,
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

export default defineConfig(({ mode }) => createViteConfig(loadEnv(mode, ".", "")));
