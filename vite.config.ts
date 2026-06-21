import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "web",
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 4001,
    strictPort: true,
    proxy: {
      "/api": "http://127.0.0.1:4000"
    }
  },
  build: {
    outDir: "../static/app",
    emptyOutDir: true
  }
});
