/**
 * The shared presentation components the app actually renders.
 *
 * These pin two accessibility decisions that were bugs: a card title must be a real heading
 * (screen readers need the section in the outline) and an empty state must *not* be a heading
 * (an H3 before the first H2 breaks the outline). The e2e accessibility journey asserts the
 * same invariants on the assembled pages.
 */
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Badge, Card, Empty, Stat } from "./ui";

describe("Card", () => {
  it("renders its title as an <h2>, so the section appears in the heading outline", () => {
    const html = renderToStaticMarkup(
      <Card title="Severity mix" subtitle="Open findings">
        <p>body</p>
      </Card>,
    );
    expect(html).toContain("<h2 class=\"card-title\">Severity mix</h2>");
    expect(html).not.toContain("<div class=\"card-title\">");
  });

  it("renders no heading when there is no title", () => {
    const html = renderToStaticMarkup(
      <Card>
        <p>body</p>
      </Card>,
    );
    expect(html).not.toContain("<h2");
  });
});

describe("Empty", () => {
  it("renders its title as text, not as a heading of an unrelated level", () => {
    const html = renderToStaticMarkup(<Empty title="Administrators only" message="Restricted." />);
    expect(html).toContain("Administrators only");
    expect(html).not.toMatch(/<h[1-6][ >]/);
  });
});

describe("Badge", () => {
  it("shows the explicit label when one is given, and humanises the value otherwise", () => {
    expect(renderToStaticMarkup(<Badge value="target.created" label="target.created" />)).toContain(
      "target.created",
    );
    expect(renderToStaticMarkup(<Badge value="auth_login_failed" />)).toContain("auth login failed");
  });
});

describe("Stat", () => {
  it("renders the label, the value and the hint", () => {
    const html = renderToStaticMarkup(<Stat label="Endpoints" value="47" hint="39 shadow" />);
    expect(html).toContain("Endpoints");
    expect(html).toContain("47");
    expect(html).toContain("39 shadow");
  });
});
