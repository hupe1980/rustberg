// SC-001/002/003 against the real App, mounted in happy-dom with the API stubbed: axe on every place
// and sheet, and two scripted walks that count the clicks a person needs. Colour contrast needs layout,
// which happy-dom has not got; contrast.test.ts checks it for both schemes from the tokens instead.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushSync, mount, unmount } from "svelte";
import axe from "axe-core";
import App from "./App.svelte";
import { forget, remember } from "./lib/session";

const identity = (name: string, roles: string[]) => ({
  principal: { id: `id-${name}`, name, principal_type: "api_key", tenant_id: "acme", roles, auth_method: "api_key" },
});
const policy = (sequence: number, source: string, note?: string) => ({
  sequence,
  version: `v${sequence}`,
  source,
  author: "id-alice",
  created_at_ms: Date.now() - 60_000,
  note,
  latest_sequence: sequence,
});
const orders = {
  "metadata-location": "file:///w/sales/orders/metadata/00000.metadata.json",
  metadata: {
    "format-version": 2,
    "table-uuid": "01a1ac06-5af7-7f22-915a-47159dcb95d6",
    location: "file:///w/sales/orders",
    schemas: [
      {
        "schema-id": 0,
        fields: [
          { id: 1, name: "order_id", required: true, type: "long" },
          { id: 2, name: "region", required: true, type: "string" },
          { id: 3, name: "email", required: false, type: "string", doc: "Contact address" },
        ],
      },
    ],
    "current-schema-id": 0,
    "partition-specs": [{ "spec-id": 0, fields: [{ "source-id": 2, "field-id": 1000, name: "region", transform: "identity" }] }],
    "default-spec-id": 0,
    properties: { owner: "sales-eng" },
  },
  "read-restrictions": {
    "required-row-filter": { type: "eq", term: "region", value: "EU" },
    "required-column-projections": [{ action: "mask", "field-id": 3 }],
  },
};

let who = identity("bob", ["analyst"]);
const seeded = () => policy(1, "permit(principal, action, resource);\n", "Seeded");
let current = seeded();
const puts: unknown[] = [];

function route(method: string, path: string, body?: string, signedIn = true): [number, unknown] {
  if (!signedIn) return [401, { error: { message: "Sign in first.", type: "NotAuthorized", code: 401 } }];
  if (path === "/auth/context") return [200, who];
  if (path === "/v1/namespaces") return [200, { namespaces: [["sales"]] }];
  if (path.startsWith("/v1/namespaces?parent=")) return [200, { namespaces: [] }];
  if (path === "/v1/namespaces/sales/tables") return [200, { identifiers: [{ namespace: ["sales"], name: "orders" }] }];
  if (path === "/v1/namespaces/sales/views") return [200, { identifiers: [] }];
  if (path === "/v1/namespaces/sales/tables/orders") return [200, orders];
  if (path === "/management/v1/policies" && method === "GET") return [200, current];
  if (path === "/management/v1/policies" && method === "PUT") {
    const { source, note } = JSON.parse(body!);
    puts.push(source);
    current = policy(current.sequence + 1, source, note);
    return [200, current];
  }
  if (path.startsWith("/management/v1/policies/history"))
    return [
      200,
      { revisions: [current, ...(current.sequence > 1 ? [seeded()] : [])].map((r) => ({ ...r, source_bytes: 10 })) },
    ];
  if (path.startsWith("/management/v1/policies/revisions/")) return [200, policy(1, "permit(principal, action, resource);\n")];
  return [404, { error: { message: `no fixture for ${method} ${path}`, type: "NotFound", code: 404 } }];
}

let app: ReturnType<typeof mount> | undefined;
let actions = 0;

async function settle() {
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 0));
    flushSync();
  }
}
async function open(hash: string) {
  location.hash = hash;
  window.dispatchEvent(new HashChangeEvent("hashchange"));
  await settle();
}
function button(name: string | RegExp): HTMLButtonElement {
  const found = [...document.querySelectorAll("button")].find((b) =>
    typeof name === "string" ? b.textContent?.trim() === name : name.test(b.textContent ?? ""),
  );
  if (!found) throw new Error(`no button ${name}`);
  return found;
}
async function click(name: string | RegExp) {
  actions++;
  button(name).click();
  await settle();
}
async function violations() {
  const result = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
  return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

beforeEach(async () => {
  vi.stubGlobal("fetch", async (path: string, init?: RequestInit) => {
    const auth = (init?.headers as Record<string, string> | undefined)?.Authorization;
    const [status, data] = route(init?.method ?? "GET", path, init?.body as string | undefined, !!auth);
    return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("matchMedia", (q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} }));
  location.hash = "";
  current = seeded();
  actions = 0;
  puts.length = 0;
});
afterEach(() => {
  if (app) unmount(app);
  app = undefined;
  forget();
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
});

async function start(as: ReturnType<typeof identity> | null) {
  if (as) {
    who = as;
    remember("rb_test_key");
  }
  app = mount(App, { target: document.body.appendChild(document.createElement("div")) });
  await settle();
}

describe("accessibility (axe, every place and sheet)", () => {
  it("sign-in", async () => {
    await start(null);
    expect(document.body.textContent).toContain("Sign in");
    expect(await violations()).toEqual([]);
  });

  it("catalog with a restricted table, policies, versions, you, connect, ⌘K", async () => {
    current = policy(2, "permit(principal, action, resource);\n// two\n", "Second");
    await start(identity("bob", ["analyst"]));
    await open("#/catalog/table/sales/orders");
    expect(document.body.textContent).toContain("Restricted");
    expect(await violations()).toEqual([]);

    await open("#/policies");
    expect(await violations()).toEqual([]);
    await open("#/policies/versions");
    expect(document.querySelector('[role="dialog"]')?.textContent).toContain("Restoring revision 1");
    expect(await violations()).toEqual([]);
    await click("Done");

    await open("#/you");
    expect(await violations()).toEqual([]);
    await click(/Connect a client/);
    expect(await violations()).toEqual([]);
    await click("Done");

    await click(/Go to/);
    expect(document.querySelector('[role="combobox"]')).not.toBeNull();
    expect(await violations()).toEqual([]);
  });
});

describe("actions a person needs", () => {
  it("⌘K finds a table the sidebar never opened, a name before an action that merely contains it", async () => {
    await start(identity("bob", ["analyst"]));
    await click(/Go to/);
    const field = document.querySelector<HTMLInputElement>('[role="combobox"]')!;
    field.value = "or";
    field.dispatchEvent(new Event("input", { bubbles: true }));
    await settle();
    const options = [...document.querySelectorAll('[role="option"]')].map((o) => o.textContent?.trim());
    expect(options[0]).toMatch(/^orders/);
  });

  it("SC-001: from /ui to a table's schema in three or fewer", async () => {
    await start(identity("bob", ["analyst"]));
    await click("sales");
    await click("orders");
    expect([...document.querySelectorAll("h2")].some((h) => h.textContent === "Schema")).toBe(true);
    expect(document.body.textContent).toContain("order_id");
    expect(actions).toBeLessThanOrEqual(3);
  });

  it("SC-002: from an edit to an installed revision in three or fewer, the diff seen first", async () => {
    await start(identity("alice", ["admin"]));
    await open("#/policies");
    await click("Edit");
    actions = 0; // the edit itself is where the walk starts
    const text = document.querySelector("textarea")!;
    text.value += "// reviewed\n";
    text.dispatchEvent(new Event("input", { bubbles: true }));
    flushSync();

    await click("Review…");
    expect(document.querySelector('[aria-label="Changes to the policy set"]')?.textContent).toContain("// reviewed");
    expect(puts).toHaveLength(0);
    await click("Save");
    expect(puts).toHaveLength(1);
    expect(document.body.textContent).toContain("Installed as revision 2");
    expect(actions).toBeLessThanOrEqual(3);
  });
});
