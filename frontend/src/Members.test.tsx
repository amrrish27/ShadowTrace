/**
 * The Members page: who may administer accounts, and that the control exists at all.
 *
 * Server-side authority is asserted in the backend suite (`test_api_users.py`); these tests
 * only pin the client contract -- an analyst is shown a refusal instead of a table, and an
 * administrator is given the invite control. Before this page existed, account management
 * required a terminal, which is the defect this release removes.
 */
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { Session } from "./App";
import { MembersPage } from "./pages/Members";

const baseProps = {
  notify: () => undefined,
  theme: "dark" as const,
  setTheme: () => undefined,
};

function session(role: Session["user"]["role"]): Session {
  return {
    user: { id: "u1", email: "someone@example.test", name: "Someone", role, org_id: "o1" },
    organization: "Example",
  };
}

describe("Members page", () => {
  it("keeps its page heading when a non-administrator is refused", () => {
    const html = renderToStaticMarkup(<MembersPage {...baseProps} session={session("analyst")} />);
    expect(html).toContain("<h1>Members</h1>");
    expect(html).toContain("Administrators only");
  });

  it("shows no member table and no invite control to a non-administrator", () => {
    const html = renderToStaticMarkup(<MembersPage {...baseProps} session={session("viewer")} />);
    expect(html).not.toContain("Invite member");
    expect(html).not.toContain("<table");
  });

  it("gives an administrator the invite control", () => {
    const html = renderToStaticMarkup(<MembersPage {...baseProps} session={session("admin")} />);
    expect(html).toContain("<h1>Members</h1>");
    expect(html).toContain("Invite member");
    expect(html).not.toContain("Administrators only");
  });
});
