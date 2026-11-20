import { describe, expect, it } from "vitest";
import { parseGrade, strength } from "./grade";

describe("the enforcement header", () => {
  it("reads every grade the server sends", () => {
    expect(parseGrade("none")).toEqual({ grade: "none", columns: [], masked: false });
    expect(parseGrade("architectural")).toEqual({ grade: "architectural", columns: [], masked: false });
    expect(parseGrade('cooperative;columns="region,ts";masked')).toEqual({
      grade: "cooperative",
      columns: ["region", "ts"],
      masked: true,
    });
    expect(parseGrade("cooperative;masked")).toEqual({ grade: "cooperative", columns: [], masked: true });
  });

  it("decodes a Display String column name", () => {
    expect(parseGrade('cooperative;columns=%"a%22b,r%c3%a9gion"')?.columns).toEqual(['a"b', "région"]);
  });

  it("claims nothing for an absent or unknown value", () => {
    expect(parseGrade(null)).toBeUndefined();
    expect(parseGrade("excellent")).toBeUndefined();
  });

  it("says why a grade is cooperative, in words", () => {
    const s = strength({ grade: "cooperative", columns: ["region"], masked: true });
    expect(s.title).toBe("Holds only in an engine that applies it");
    expect(s.detail).toContain("region");
    expect(s.detail).toContain("unmasked");
  });
});
