import { describe as suite, expect, it } from "vitest";
import { describe } from "./predicate";

const names = new Map([[1, "region"], [2, "amount"]]);

suite("a row filter, as a person reads it", () => {
  it("names a field id's column and quotes a string", () => {
    expect(describe({ type: "eq", left: { type: "reference", id: 1 }, right: { type: "literal", value: "EU" } }, names)).toBe(
      "region = 'EU'",
    );
  });
  it("reads the term/value spelling and nests with parentheses where needed", () => {
    const e = {
      type: "or",
      left: { type: "eq", term: "region", value: "EU" },
      right: { type: "and", left: { type: "gt", term: "amount", value: 10 }, right: { type: "not-null", term: "region" } },
    };
    expect(describe(e, names)).toBe("region = 'EU' or (amount > 10 and region is not null)");
  });
  it("says what a constant filter means", () => {
    expect(describe({ type: "false" }, names)).toBe("no rows");
    expect(describe(true, names)).toBe("every row");
  });
});
