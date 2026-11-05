// `just shots`: the console's documentation screenshots, light and dark, taken from the real server —
// so what they show (bob restricted, alice not) is enforcement, not a mock. Starts the debug binary
// on a free loopback port with two API keys and a seeded catalog, drives a locally installed Chrome
// (puppeteer-core never downloads one), and writes WebP files to site/static/console/.

import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { spawn, execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer-core";

const repo = fileURLToPath(new URL("../..", import.meta.url));
const out = join(repo, "site/static/console");
const binary = process.env.RUSTBERG_BIN ?? join(repo, "target/debug/rustberg");
const keys = { alice: "rb_docs_admin_key_0000000000000000000000000", bob: "rb_docs_analyst_key_00000000000000000000000" };

function chrome() {
  const candidates = [process.env.CHROME, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Chromium.app/Contents/MacOS/Chromium"];
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    try {
      candidates.push(execFileSync("which", [name]).toString().trim());
    } catch {
      /* not installed */
    }
  }
  const found = candidates.find((c) => c && existsSync(c));
  if (!found) throw new Error("No Chrome or Chromium found; set CHROME to its path.");
  return found;
}

// 8000 when it is free, because the client snippets on screen show it; any free port otherwise.
const freePort = (preferred) =>
  new Promise((resolve) => {
    const s = createServer();
    s.once("error", () => resolve(freePort(0)));
    s.listen(preferred, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

const policy = `// Administrators: everything in their own tenant, including policy.
permit(
  principal in Rustberg::Group::"admin",
  action,
  resource
) when { resource.tenant == principal.tenant };

// Analysts read EU orders only, and never see a customer's email.
@row_filter("{\\"type\\":\\"eq\\",\\"term\\":\\"region\\",\\"value\\":\\"EU\\"}")
@column_mask("email")
permit(
  principal in Rustberg::Group::"analyst",
  action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
  resource
) when { resource.tenant == principal.tenant };
`;
const marketing = `
// Marketing may list everything.
permit(
  principal in Rustberg::Group::"marketing",
  action == Rustberg::Action::"List",
  resource
) when { resource.tenant == principal.tenant };
`;

if (!existsSync(binary)) throw new Error(`${binary} not found: run \`just ui && cargo build\` first.`);
// A short, fixed path, because a table's location is on screen.
const dir = "/tmp/rustberg";
rmSync(dir, { recursive: true, force: true });
mkdirSync(dir);
const port = await freePort(8000);
const base = `http://127.0.0.1:${port}`;
writeFileSync(join(dir, "policies.cedar"), policy);
writeFileSync(
  join(dir, "config.toml"),
  `[server]
host = "127.0.0.1"
port = ${port}

[server.auth]
api_key_enabled = true
policy_file = "${dir}/policies.cedar"

[[server.auth.api_keys]]
name = "alice"
tenant = "acme"
roles = ["admin"]
key_env = "DOCS_ALICE_KEY"

[[server.auth.api_keys]]
name = "bob"
tenant = "acme"
roles = ["analyst"]
key_env = "DOCS_BOB_KEY"

[storage]
catalog_url = "file://${dir}/data"
warehouse_location = "file://${dir}/warehouse"

[audit]
sink = "none"
`,
);

const server = spawn(binary, ["--config", join(dir, "config.toml"), "--insecure-http"], {
  env: { ...process.env, DOCS_ALICE_KEY: keys.alice, DOCS_BOB_KEY: keys.bob, RUST_LOG: "error" },
  stdio: ["ignore", "ignore", "inherit"],
});

async function api(method, path, body) {
  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${keys.alice}`, "Content-Type": "application/json" },
    body: body && JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
  return res.json();
}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
let browser;
try {
  for (let i = 0; ; i++) {
    try {
      await api("GET", "/auth/context");
      break;
    } catch (e) {
      if (i > 100) throw e;
      await pause(100);
    }
  }

  const field = (id, name, type, required, doc) => ({ id, name, type, required, ...(doc && { doc }) });
  const table = (ns, name, fields, extra = {}) =>
    api("POST", `/v1/namespaces/${ns}/tables`, { name, schema: { type: "struct", "schema-id": 0, fields }, ...extra });
  for (const ns of ["sales", "marketing"]) await api("POST", "/v1/namespaces", { namespace: [ns] });
  await table(
    "sales",
    "orders",
    [
      field(1, "order_id", "long", true),
      field(2, "region", "string", true),
      field(3, "customer", "string", false),
      field(4, "email", "string", false, "Contact address — personal data"),
      field(5, "amount", "decimal(12, 2)", false),
      field(6, "ordered_at", "timestamptz", false),
    ],
    {
      "partition-spec": { "spec-id": 0, fields: [{ "source-id": 2, "field-id": 1000, name: "region", transform: "identity" }] },
      properties: { comment: "One row per order", owner: "sales-eng" },
    },
  );
  await table("sales", "customers", [field(1, "id", "long", true), field(2, "name", "string", false)]);
  await table("marketing", "campaigns", [field(1, "id", "long", true), field(2, "title", "string", false)]);
  await api("PUT", "/management/v1/policies", { source: policy + marketing, note: "Allow marketing to list" });

  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  browser = await puppeteer.launch({ executablePath: chrome(), headless: true, args: ["--no-proxy-server"] });
  const written = [];

  for (const scheme of ["light", "dark"]) {
    const errors = [];
    const as = async (who) => {
      const page = await browser.newPage();
      await page.setViewport({ width: 1180, height: 740, deviceScaleFactor: 2 });
      await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
      page.on("pageerror", (e) => errors.push(e.message));
      await page.evaluateOnNewDocument((k) => sessionStorage.setItem("rustberg.credential", k), keys[who]);
      return page;
    };
    const open = async (page, hash) => {
      await page.goto(`${base}/ui/${hash}`, { waitUntil: "networkidle0" });
      await pause(300);
    };
    // A focus ring is the capture's doing, not the reader's; the review keeps its note field's.
    const shot = async (page, name, keepFocus = false) => {
      if (!keepFocus) await page.evaluate(() => document.activeElement?.blur());
      await pause(400);
      const file = join(out, `${name}-${scheme}.webp`);
      await page.screenshot({ path: file, type: "webp", quality: 88 });
      written.push(file);
    };
    const click = async (page, text) => {
      const found = await page.evaluate((t) => {
        const b = [...document.querySelectorAll("button")].find((b) => b.textContent.trim().startsWith(t));
        b?.click();
        return !!b;
      }, text);
      if (!found) throw new Error(`no button "${text}"`);
      await pause(300);
    };

    const bob = await as("bob");
    await open(bob, "#/catalog/table/sales/orders");
    await shot(bob, "table-restricted");
    await click(bob, "Go to");
    await bob.keyboard.type("ord");
    await shot(bob, "palette", true);
    await bob.keyboard.press("Escape");
    await open(bob, "#/you");
    await click(bob, "Connect a client");
    await shot(bob, "connect");
    await bob.close();

    const alice = await as("alice");
    await open(alice, "#/catalog/table/sales/orders");
    await shot(alice, "table-unrestricted");
    await open(alice, "#/policies/versions");
    await click(alice, "1");
    await shot(alice, "versions");
    await click(alice, "Done");
    await click(alice, "Edit");
    await alice.evaluate(() => {
      const t = document.querySelector("textarea");
      t.value = t.value.replace(
        'Group::"marketing",\n  action == Rustberg::Action::"List",',
        'Group::"marketing",\n  action in [Rustberg::Action::"List", Rustberg::Action::"Read"],',
      );
      t.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await click(alice, "Review");
    await alice.type("[role=dialog] input", "Marketing may read what it lists");
    await shot(alice, "review", true);
    await alice.close();

    if (errors.length) throw new Error(`page errors (${scheme}): ${errors.join("; ")}`);
  }
  console.log(`${written.length} screenshots in ${out}`);
} finally {
  await browser?.close();
  server.kill();
  rmSync(dir, { recursive: true, force: true });
}
