import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The built bundle is served by the FastAPI app (frontend/dist is mounted at /assets).
// No inline scripts are emitted, so the CSP in deploy/proxy/nginx.conf stays strict.
export default defineConfig({
  plugins: [react()],
  // Unit tests live next to the source; e2e/ belongs to Playwright, not Vitest.
  test: {
    include: ["src/**/*.test.{ts,tsx}"],
    exclude: ["e2e/**", "node_modules/**", "dist/**"],
  },
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    target: "es2020",
  },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: false },
    },
  },
});
