import { describe, expect, it } from "vitest";
import { ApiError, formatTimestamp } from "./api";

describe("formatTimestamp", () => {
  it("renders an em dash for missing values", () => {
    expect(formatTimestamp(null)).toBe("—");
    expect(formatTimestamp(undefined)).toBe("—");
    expect(formatTimestamp(0)).toBe("—");
  });

  it("renders epoch seconds as a locale string", () => {
    const rendered = formatTimestamp(1_700_000_000);
    expect(rendered).not.toBe("—");
    expect(rendered.length).toBeGreaterThan(4);
  });
});

describe("ApiError", () => {
  it("keeps the server error code, message and request id", () => {
    const error = new ApiError(403, { code: "forbidden", message: "No.", request_id: "abc123" });
    expect(error.status).toBe(403);
    expect(error.code).toBe("forbidden");
    expect(error.message).toBe("No.");
    expect(error.requestId).toBe("abc123");
    expect(error).toBeInstanceOf(Error);
  });
});
