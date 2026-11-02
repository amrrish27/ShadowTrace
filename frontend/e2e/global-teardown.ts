/**
 * Stops the ShadowLab process that `global-setup.ts` started, so a test run leaves no
 * stray listener behind. Only the PID recorded by the setup is signalled — never a
 * pattern match — so a lab started by hand for other work is left alone.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";

const PID_FILE = "/tmp/st_e2e_lab.pid";

export default async function globalTeardown(): Promise<void> {
  try {
    const pid = Number(fs.readFileSync(PID_FILE, "utf8").trim());
    if (Number.isInteger(pid) && pid > 0) {
      execFileSync("kill", [String(pid)], { stdio: "ignore" });
    }
  } catch {
    // No PID file (an already-running lab was reused) or already gone: nothing to do.
  } finally {
    fs.rmSync(PID_FILE, { force: true });
  }
}
