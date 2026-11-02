/**
 * The Overview payload contract, shared with the backend.
 *
 * `src/__fixtures__/overview.contract.json` is the same shape `backend/tests/test_api_dashboard.py`
 * asserts against the live endpoint; these tests keep the client's defensive normaliser honest.
 * They used to live in `Dashboard.test.tsx`, next to a component the app no longer renders.
 */
import { describe, expect, it } from "vitest";
import contract from "./__fixtures__/overview.contract.json";
import type { Overview } from "./api";
import { normalizeOverview } from "./api";

const EMPTY = contract.empty as Overview;
const POPULATED = contract.populated as Overview;

describe("Overview contract", () => {
  it("declares exactly the keys the backend returns", () => {
    expect(Object.keys(EMPTY).sort()).toEqual([...contract.keys].sort());
    expect(Object.keys(POPULATED).sort()).toEqual([...contract.keys].sort());
  });

  it("normalises a payload that is missing every optional block", () => {
    const normalised = normalizeOverview({});
    expect(normalised.recent_findings).toEqual([]);
    expect(normalised.source_breakdown).toEqual([]);
    expect(normalised.recent_scans).toEqual([]);
    expect(normalised.scan_timeline).toEqual([]);
    expect(normalised.findings_by_severity).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    expect(normalised.endpoints).toEqual({ total: 0, shadow: 0, documented: 0, zombie: 0 });
    expect(normalised.targets).toEqual({ total: 0, approved: 0 });
  });

  it("normalises the legacy payload that caused the crash (no recent_findings key)", () => {
    const legacy = { ...EMPTY } as Partial<Overview>;
    delete legacy.recent_findings;
    const normalised = normalizeOverview(legacy);
    expect(normalised.recent_findings).toEqual([]);
    expect(Object.keys(normalised).sort()).toEqual([...contract.keys].sort());
  });

  it("treats null, undefined and non-array values as empty", () => {
    const messy = normalizeOverview({
      recent_findings: null,
      recent_scans: "nope",
      source_breakdown: undefined,
      scan_timeline: 7,
    } as unknown as Partial<Overview>);
    expect(messy.recent_findings).toEqual([]);
    expect(messy.recent_scans).toEqual([]);
    expect(messy.source_breakdown).toEqual([]);
    expect(messy.scan_timeline).toEqual([]);
  });
});
