/**
 * Playwright global setup: make the environment the journeys need.
 *
 * 1. Start the bundled ShadowLab on `ST_E2E_LAB_PORT` (idempotent: reuse a healthy one).
 * 2. Remove the previous database so every run starts from a known state.
 * 3. Seed a least-privilege demo analyst, an administrator in the same organization, and
 *    one completed scan with `scripts/seed_demo.py --with-admin --with-scan`. The two
 *    identities let the journeys prove both "an analyst is refused" and "an admin sees it".
 *
 * The seed runs Python directly against the same SQLite file the API will open, so the
 * UI has a completed scan with real endpoints and findings to render.
 */
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const python = process.env.ST_E2E_PYTHON ?? "python3";
const labPort = Number(process.env.ST_E2E_LAB_PORT ?? 8099);
const database = process.env.ST_E2E_DB ?? "/tmp/st_e2e.db";
export const EMAIL = process.env.ST_E2E_EMAIL ?? "demo@shadowtrace.local";
export const PASSWORD = process.env.ST_E2E_PASSWORD ?? "E2E-Demo-Pass-9!x";
export const ADMIN_EMAIL = process.env.ST_E2E_ADMIN_EMAIL ?? "admin@shadowtrace.local";
export const ADMIN_PASSWORD = process.env.ST_E2E_ADMIN_PASSWORD ?? "E2E-Admin-Pass-9!x";

async function labIsUp(): Promise<boolean> {
  try {
    const response = await fetch(`http://127.0.0.1:${labPort}/health`, { signal: AbortSignal.timeout(1500) });
    return response.ok;
  } catch {
    return false;
  }
}

async function waitForLab(timeoutMs = 60_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await labIsUp()) return;
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error(`ShadowLab did not become healthy on port ${labPort}`);
}

export default async function globalSetup(): Promise<void> {
  if (!(await labIsUp())) {
    const lab = spawn(python, ["lab/app/lab.py", "--port", String(labPort)], {
      cwd: repoRoot,
      detached: true,
      stdio: "ignore",
    });
    lab.unref(); // outlives this process; global-teardown stops it by PID
    if (lab.pid) fs.writeFileSync("/tmp/st_e2e_lab.pid", String(lab.pid));
    await waitForLab();
  }

  for (const suffix of ["", "-wal", "-shm"]) {
    fs.rmSync(`${database}${suffix}`, { force: true });
  }

  const env = {
    ...process.env,
    ST_ENV: "test",
    ST_DATABASE_PATH: database,
    ST_PRIVATE_ALLOWLIST: `127.0.0.1:${labPort}`,
    ST_SCANNING_ENABLED: "true",
  };
  const seed = spawnSync(
    python,
    [
      "scripts/seed_demo.py",
      "--password", PASSWORD,
      "--email", EMAIL,
      "--base-url", `http://127.0.0.1:${labPort}`,
      "--with-admin",
      "--admin-email", ADMIN_EMAIL,
      "--admin-password", ADMIN_PASSWORD,
      "--with-scan",
    ],
    { cwd: repoRoot, env, encoding: "utf8", timeout: 300_000 },
  );
  if (seed.status !== 0) {
    throw new Error(`seed_demo.py failed (exit ${seed.status}):\n${seed.stdout}\n${seed.stderr}`);
  }
  process.stdout.write(`${seed.stdout}\n`);
}
