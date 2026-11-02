/**
 * Playwright configuration for the end-to-end journeys.
 *
 * Everything is driven by environment variables so the same config works locally, in the
 * Docker composition and in CI:
 *
 *   ST_E2E_BASE_URL   base URL of the app under test   (default http://127.0.0.1:8000)
 *   ST_E2E_DB         SQLite file the API and the seeder share (default /tmp/st_e2e.db)
 *   ST_E2E_LAB_PORT   port for the bundled ShadowLab    (default 8099)
 *   ST_E2E_EMAIL / ST_E2E_PASSWORD  the seeded demo account
 *
 * `globalSetup` starts the lab, then seeds a demo analyst **and one completed scan** with
 * `scripts/seed_demo.py --with-scan`; `webServer` starts uvicorn against the same database.
 * Run with `npm run e2e` (or `npx playwright test`).
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, devices } from "@playwright/test";

// `package.json` sets "type": "module", so `__dirname` does not exist here.
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const port = Number(process.env.ST_E2E_PORT ?? 8000);
const baseURL = process.env.ST_E2E_BASE_URL ?? `http://127.0.0.1:${port}`;
const database = process.env.ST_E2E_DB ?? "/tmp/st_e2e.db";
const labPort = process.env.ST_E2E_LAB_PORT ?? "8099";
const python = process.env.ST_E2E_PYTHON ?? "python3";

export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: { timeout: 20_000 },
  fullyParallel: false, // one worker container, one database
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  forbidOnly: !!process.env.CI,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
    ...devices["Desktop Chrome"],
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // The API serves the built SPA from frontend/dist, so the build must exist first
  // (`npm run build`). Playwright starts it here rather than assuming a running server.
  webServer: {
    command: `${python} -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port ${port}`,
    cwd: repoRoot,
    url: `${baseURL}/api/v1/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    stdout: "pipe" as const,
    stderr: "pipe" as const,
    // The deployment is configured exactly as the README quick start does: base URL and
    // CORS on `localhost:8000` while the browser drives `127.0.0.1:<port>`. That is the
    // shape that used to 403 with "The request could not be verified.", so the journey
    // keeps it — do not "fix" it by pointing CORS at the test origin.
    env: {
      ST_ENV: "test",
      ST_DATABASE_PATH: database,
      ST_ALLOWED_HOSTS: `localhost,127.0.0.1`,
      ST_BASE_URL: "http://localhost:8000",
      ST_CORS_ORIGINS: "http://localhost:8000",
      ST_COOKIE_SECURE: "false",
      ST_PRIVATE_ALLOWLIST: `127.0.0.1:${labPort}`,
      ST_SCANNING_ENABLED: "true",
      ST_LOG_LEVEL: "INFO",
    },
  },
});
