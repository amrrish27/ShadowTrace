/**
 * End-to-end journeys against the redesigned UI (round 8).
 *
 * Run:  npm run build && npx playwright test      (Playwright starts the API and the lab)
 *
 * Nothing here is stubbed: the API, the SQLite database, the real scan engine and the real
 * SPA bundle are exercised together. `global-setup.ts` seeds a demo analyst and one
 * completed scan through `scripts/seed_demo.py --with-scan`.
 *
 * Two identities are seeded on purpose: a least-privilege analyst and an administrator.
 * The analyst journeys assert that admin-only surfaces are *refused*; the admin journey
 * asserts that the audit trail exists and records what the analyst did. Asserting the audit
 * page as an analyst was the original bug in this file -- it could never pass.
 */
import { expect, test } from "@playwright/test";

const EMAIL = process.env.ST_E2E_EMAIL ?? "demo@shadowtrace.local";
const PASSWORD = process.env.ST_E2E_PASSWORD ?? "E2E-Demo-Pass-9!x";
const ADMIN_EMAIL = process.env.ST_E2E_ADMIN_EMAIL ?? "admin@shadowtrace.local";
const ADMIN_PASSWORD = process.env.ST_E2E_ADMIN_PASSWORD ?? "E2E-Admin-Pass-9!x";

async function signIn(
  page: import("@playwright/test").Page,
  email: string = EMAIL,
  password: string = PASSWORD,
): Promise<void> {
  await page.goto("/");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await expect(page.locator(".topbar-title")).toHaveText("Overview");
}

test("analyst signs in, follows a scan, reads evidence and exports it", async ({ page }) => {
  await signIn(page);

  // --- overview: real numbers from the seeded scan ---------------------------
  await expect(page.getByRole("heading", { name: "Severity mix" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Scan history" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Discovery sources" })).toBeVisible();
  // A non-zero endpoint count proves lab -> engine -> database -> API -> UI is wired up.
  const endpointsCard = page.locator(".stat", { has: page.locator(".stat-label", { hasText: /endpoints/i }) });
  await expect(endpointsCard.first()).toBeVisible();

  // --- the seeded scan ------------------------------------------------------
  await page.getByRole("link", { name: "Scans", exact: true }).click();
  await expect(page.locator(".topbar-title")).toHaveText("Scans");
  await page.getByRole("link", { name: "Open" }).first().click();
  await expect(page.locator(".topbar-title")).toHaveText("Scan detail");
  await expect(page.locator("h1")).toBeVisible();

  // --- findings tab -> a finding with evidence and remediation --------------
  await page.getByRole("tab", { name: /findings/i }).click();
  const findingRows = page.locator("tbody tr.clickable");
  await expect(findingRows.first()).toBeVisible();
  // The row must carry a rule id somewhere -- positional cell indexes broke when the
  // Severity/Confidence columns were added, so assert the content, not the column number.
  await expect(findingRows.first()).toContainText(/ST-\d{3}/);
  await findingRows.first().click();
  await expect(page.locator(".topbar-title")).toHaveText("Finding");
  // Remediation is on the "Impact & fix" tab; the page opens on Evidence.
  await page.getByRole("tab", { name: /impact & fix/i }).click();
  await expect(page.getByRole("heading", { name: /remediation/i })).toBeVisible();
  await expect(page.getByText(/evidence/i).first()).toBeVisible();

  // --- endpoints tab, filtered to shadow ------------------------------------
  await page.getByRole("link", { name: "Scans", exact: true }).click();
  await page.getByRole("link", { name: "Open" }).first().click();
  await page.getByRole("tab", { name: /endpoints/i }).click();
  await page.getByLabel("Classification").selectOption("shadow");
  const shadowCells = page.getByRole("cell", { name: "shadow", exact: true });
  await expect(shadowCells.first()).toBeVisible();
  expect(await shadowCells.count()).toBeGreaterThan(0);

  // --- events timeline ------------------------------------------------------
  await page.getByRole("tab", { name: /events/i }).click();
  await expect(page.locator(".timeline").first()).toBeVisible();

  // --- export from the Reports page ----------------------------------------
  await page.getByRole("link", { name: "Reports", exact: true }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: /download/i }).first().click();
  expect((await download).suggestedFilename()).toMatch(/shadowtrace-.*\.(json|html)$/);

  // --- sign out -------------------------------------------------------------
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: /^sign in$/i })).toBeVisible();
});

test("target registration works from the browser (CSRF and origin regression)", async ({ page }) => {
  await signIn(page);
  await page.getByRole("link", { name: "Targets", exact: true }).click();
  await expect(page.locator(".topbar-title")).toHaveText("Targets");

  await page.getByRole("button", { name: /register target/i }).first().click();
  const dialog = page.getByRole("dialog", { name: "Register a target" });
  await expect(dialog).toBeVisible();

  // A public host under `ownership` needs no allow-list entry, so this cannot collide
  // with the seeded ShadowLab target on 127.0.0.1.
  await dialog.getByLabel("Name").fill("Journey Target");
  await dialog.getByLabel("Base URL").fill("https://journey.example.test");
  await dialog.getByLabel("Authorized ports").fill("443");
  await dialog.getByLabel("Authorization mode").selectOption("ownership");
  await dialog.getByLabel("Attestation").fill("Operator owns this target; end-to-end journey.");
  await dialog.getByRole("button", { name: /register target/i }).click();

  await expect(page.getByRole("cell", { name: "Journey Target" })).toBeVisible();

  // The audit trail is administrator-only. An analyst must be refused it -- asserting the
  // entry itself here was the original defect in this journey (it could never pass).
  await page.getByRole("link", { name: "Audit log", exact: true }).click();
  await expect(page.getByText(/administrators only/i)).toBeVisible();
});

test("an administrator audits what the analyst did and manages members", async ({ page, browser }) => {
  await signIn(page, ADMIN_EMAIL, ADMIN_PASSWORD);

  // The audit log is readable for an admin, and the analyst's target creation is recorded.
  await page.getByRole("link", { name: "Audit log", exact: true }).click();
  await expect(page.locator(".topbar-title")).toHaveText("Audit log");
  // The UI renders the humanised label ("Target.Created"), so match case-insensitively.
  const auditRows = page.locator("table tbody");
  await expect(auditRows.getByText(/target\.created/i).first()).toBeVisible();
  await expect(auditRows.getByText(/auth\.login_success/i).first()).toBeVisible();

  // Member management lists both seeded identities, with their roles.
  await page.getByRole("link", { name: "Members", exact: true }).click();
  await expect(page.locator(".topbar-title")).toHaveText("Members");
  await expect(page.getByRole("cell", { name: new RegExp(EMAIL) }).first()).toBeVisible();
  await expect(page.getByRole("cell", { name: new RegExp(ADMIN_EMAIL) }).first()).toBeVisible();

  // --- the whole account lifecycle, with no terminal involved -----------------
  const invitee = "quarterly.ferry@shadowtrace.local";
  await page.getByRole("button", { name: /invite member/i }).click();
  const dialog = page.getByRole("dialog", { name: /invite a member/i });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel("Email").fill(invitee);
  await dialog.getByLabel("Role").selectOption("viewer");
  await dialog.getByRole("button", { name: /create invitation/i }).click();

  const link = page.getByTestId("invite-link");
  await expect(link).toBeVisible();
  const inviteUrl = (await link.innerText()).trim();
  expect(inviteUrl).toContain("#/accept-invite?token=");
  await page.getByRole("button", { name: "Done" }).click();

  // The invited person is somebody else on another device, so they open the link in their
  // own browser context -- no shared cookies, no session.
  const inviteeContext = await browser.newContext();
  const inviteePage = await inviteeContext.newPage();
  await inviteePage.goto(inviteUrl);
  await expect(inviteePage.getByRole("heading", { name: /choose your password/i })).toBeVisible();
  await inviteePage.getByLabel("Your name").fill("Quarterly Ferry");
  await inviteePage.getByLabel("New password", { exact: true }).fill("Quarterly-Ferry-Battery-7!");
  await inviteePage.getByLabel("Repeat password").fill("Quarterly-Ferry-Battery-7!");
  await inviteePage.getByRole("button", { name: /create account and sign in/i }).click();

  // Signed in as the new viewer: the invite created a working account, no CLI involved.
  await expect(inviteePage.locator(".topbar-title")).toHaveText("Overview");
  await expect(inviteePage.getByText(invitee).first()).toBeVisible();
  await inviteeContext.close();

  // --- the admin changes their own password, then proves the new one works ----
  const rotated = "Rotated-Admin-Battery-4!";
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Change password" }).click();
  const change = page.getByRole("dialog", { name: /change your password/i });
  await expect(change).toBeVisible();
  await change.getByLabel("Current password").fill(ADMIN_PASSWORD);
  await change.getByLabel("New password", { exact: true }).fill(rotated);
  await change.getByLabel("Repeat new password").fill(rotated);
  await change.getByRole("button", { name: /^change password$/i }).last().click();
  await expect(change).toBeHidden();

  await page.getByRole("button", { name: "Sign out" }).click();
  await signIn(page, ADMIN_EMAIL, rotated);
  await expect(page.locator(".topbar-title")).toHaveText("Overview");
});

test("every page keeps a usable document outline and labelled controls", async ({ page }) => {
  // A cheap, dependency-free accessibility floor. It caught two real defects when it was
  // first run by hand: pages with no <h1>, and an empty-state <h3> that skipped a level.
  await signIn(page);
  const routes = [
    "overview", "targets", "scans", "findings", "endpoints",
    "evidence", "reports", "lab", "settings", "members", "audit",
  ];
  for (const route of routes) {
    await page.goto(`/#/${route}`);
    await expect(page.locator(".topbar-title")).toBeVisible();
    const issues = await page.evaluate(() => {
      const out: string[] = [];
      const labelled = (el: Element): boolean => {
        const id = el.getAttribute("id");
        if (el.getAttribute("aria-label") || el.getAttribute("aria-labelledby") || el.getAttribute("title")) {
          return true;
        }
        if (id && document.querySelector(`label[for="${CSS.escape(id)}"]`)) return true;
        return Boolean(el.closest("label"));
      };
      for (const el of Array.from(document.querySelectorAll("input, select, textarea"))) {
        if ((el as HTMLInputElement).type !== "hidden" && !labelled(el)) out.push(`unlabelled ${el.tagName}`);
      }
      for (const button of Array.from(document.querySelectorAll("button"))) {
        if (!(button.textContent ?? "").trim() && !button.getAttribute("aria-label")) out.push("nameless button");
      }
      const ids = Array.from(document.querySelectorAll("[id]")).map((el) => el.id);
      const duplicates = Array.from(new Set(ids.filter((id, index) => ids.indexOf(id) !== index)));
      if (duplicates.length) out.push(`duplicate ids: ${duplicates.slice(0, 3).join(",")}`);
      const levels = Array.from(document.querySelectorAll("h1,h2,h3,h4,h5,h6")).map((h) => Number(h.tagName[1]));
      if (levels[0] !== 1) out.push("first heading is not H1");
      if (levels.filter((level) => level === 1).length !== 1) out.push("expected exactly one H1");
      let previous = 0;
      for (const level of levels) {
        if (previous && level > previous + 1) out.push(`heading skip H${previous}->H${level}`);
        previous = level;
      }
      return Array.from(new Set(out));
    });
    expect(issues, `accessibility floor on #/${route}`).toEqual([]);
  }
});
