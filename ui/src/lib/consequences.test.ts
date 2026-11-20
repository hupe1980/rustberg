import { describe, expect, it } from "vitest";
import type { Impact } from "./api";
import { coverage, grouped, sentence, who } from "./consequences";

const impact: Impact = {
  checked: {
    principals: [
      { kind: "group", id: "member of marketing", roles: ["marketing"] },
      { kind: "anyone", id: "anyone", roles: [] },
    ],
    tables: 2,
    evaluations: 16,
    truncated: false,
    "unchecked-tables": 0,
  },
  changes: [
    {
      principal: { kind: "group", id: "member of marketing", roles: ["marketing"] },
      resource: "sales.orders",
      action: "Read",
      change: "gains",
      after: { grade: "cooperative", header: "cooperative;masked" },
    },
    {
      principal: { kind: "group", id: "member of marketing", roles: ["marketing"] },
      resource: "policy set",
      action: "Manage",
      change: "gains",
    },
  ],
  note: "Exact for the principals and tables listed; not a proof for anyone else.",
};

describe("consequences, in words", () => {
  it("names who in a person's terms", () => {
    expect(who({ kind: "group", id: "member of eu", roles: ["eu"] })).toBe("Members of eu");
    expect(who({ kind: "api_key", id: "etl", roles: [] })).toBe("API key etl");
    expect(who({ kind: "anyone", id: "anyone", roles: [] })).toBe("Anyone in no group");
  });

  it("says what was gained and how strongly it holds", () => {
    expect(sentence(impact.changes[0]!)).toBe(
      "gains Read on sales.orders (restricted — holds only in an engine that applies it)",
    );
    expect(sentence(impact.changes[1]!)).toBe("gains Manage on the policy set");
  });

  it("groups by principal", () => {
    expect(grouped(impact)).toHaveLength(1);
    expect(grouped(impact)[0]!.changes).toHaveLength(2);
  });

  it("says what it checked, and partial when it was cut", () => {
    expect(coverage(impact)).toContain("not a proof");
    expect(coverage({ ...impact, checked: { ...impact.checked, truncated: true, "unchecked-tables": 7 } })).toContain(
      "partial: 7 more tables",
    );
  });
});
