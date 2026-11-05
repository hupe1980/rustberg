import { afterEach, describe, expect, it, vi } from "vitest";
import { credential, forget, remember } from "./session";
import { call, nsPath } from "./api";
import { changes, diff, fold } from "./diff";
import { tokenize } from "./cedar";
import { masked, snippets } from "./snippets";

afterEach(() => {
  sessionStorage.clear();
  localStorage.clear();
  vi.unstubAllGlobals();
});

describe("session", () => {
  it("keeps the credential in this tab's session storage, and nowhere else", () => {
    remember("  rb_secret  ");
    expect(credential()).toBe("rb_secret");
    expect(localStorage.length).toBe(0);
    expect(document.cookie).toBe("");
    forget();
    expect(credential()).toBeNull();
  });

  it("sends it as a bearer header, never in the URL, and forgets it when the server rejects it", async () => {
    remember("rb_secret");
    const seen: { url: string; auth: string | null }[] = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      seen.push({ url, auth: new Headers(init.headers).get("Authorization") });
      return new Response(JSON.stringify({ error: { message: "Invalid API key", type: "NotAuthorizedException", code: 401 } }), {
        status: 401,
      });
    });
    await expect(call("GET", "/auth/context")).rejects.toMatchObject({ status: 401, message: "Invalid API key" });
    expect(seen[0]!.auth).toBe("Bearer rb_secret");
    expect(seen[0]!.url).not.toContain("rb_secret");
    expect(credential()).toBeNull();
  });
});

describe("paths", () => {
  it("joins a nested namespace with the unit separator", () => {
    expect(nsPath(["a", "b c"])).toBe("a%1Fb%20c");
  });
});

describe("diff", () => {
  it("shows what changed and keeps the rest", () => {
    const lines = diff("a\nb\nc", "a\nB\nc\nd");
    expect(lines.map((l) => `${l.kind[0]}${l.text}`)).toEqual(["sa", "db", "aB", "sc", "ad"]);
    expect(changes(lines)).toEqual({ added: 2, removed: 1 });
  });
  it("finds nothing to change in identical text", () => {
    expect(changes(diff("x\ny", "x\ny"))).toEqual({ added: 0, removed: 0 });
  });
});

describe("cedar emphasis", () => {
  it("marks keywords, annotations, strings and comments, and keeps every character", () => {
    const line = '@row_filter("{\\"a\\":1}") permit(principal in Rustberg::Group::"eu", action, resource) // why';
    const tokens = tokenize(line);
    expect(tokens.map((t) => t.text).join("")).toBe(line);
    expect(tokens.find((t) => t.kind === "ann")?.text).toBe("@row_filter");
    expect(tokens.filter((t) => t.kind === "kw").map((t) => t.text)).toEqual(["permit", "principal", "in", "action", "resource"]);
    expect(tokens.at(-1)).toEqual({ kind: "com", text: "// why" });
  });
});

describe("connect", () => {
  it("fills in this server and the credential, for every client", () => {
    for (const s of snippets) {
      const code = s.code("https://catalog.example", "rb_key", "s3://wh");
      expect(code, s.id).toContain("https://catalog.example");
      expect(code, s.id).toContain("rb_key");
    }
  });
  // The form proven against DuckDB 1.4: a token only through a secret, attached by the server's warehouse.
  it("gives DuckDB its token through a secret and attaches by warehouse", () => {
    const code = snippets.find((s) => s.id === "duckdb")!.code("https://catalog.example", "rb_key", "s3://wh");
    expect(code).toContain("CREATE SECRET rustberg (TYPE iceberg, TOKEN 'rb_key')");
    expect(code).toContain("ATTACH 's3://wh' AS rustberg (TYPE iceberg, SECRET rustberg, ENDPOINT 'https://catalog.example')");
    expect(code).not.toContain("CREDENTIAL");
  });
  it("masks a credential to something recognisable but unusable", () => {
    expect(masked("rb_0123456789abcdef")).toBe("rb_0••••••••••••cdef");
    expect(masked("short")).toBe("•••••");
  });
});

describe("fold", () => {
  const long = Array.from({ length: 20 }, (_, i) => `line ${i + 1}`).join("\n");
  it("collapses unchanged runs far from a change and keeps three lines of context", () => {
    const rows = fold(diff(long, long.replace("line 10", "line ten")));
    const folds = rows.filter((r) => r.kind === "fold");
    expect(folds.map((f) => (f.kind === "fold" ? f.lines.length : 0))).toEqual([6, 7]);
    expect(rows.filter((r) => r.kind !== "fold")).toHaveLength(8);
  });
  it("leaves an unchanged document alone", () => {
    expect(fold(diff(long, long)).every((r) => r.kind === "same")).toBe(true);
  });
});
