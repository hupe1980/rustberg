<script lang="ts">
  // The window: a glass sidebar (places, then the catalog outline), a glass toolbar that always says whose
  // view this is, and solid content. One sheet at a time; ⌘K finds anything.
  import Symbol from "./components/Symbol.svelte";
  import Palette, { type Command } from "./components/Palette.svelte";
  import Connect from "./components/Connect.svelte";
  import Outline, { type Known, type Selection } from "./components/Outline.svelte";
  import Catalog from "./places/Catalog.svelte";
  import Policies from "./places/Policies.svelte";
  import You from "./places/You.svelte";
  import { ApiError, get, listNamespaces, listTables, listViews, nsPath, whenUnauthorized, type Ident, type Identity } from "./lib/api";
  import { credential, forget, remember } from "./lib/session";
  import { copy } from "./lib/clipboard";
  import { ident } from "./lib/format";

  type Place = "catalog" | "policies" | "you";

  let phase = $state<"starting" | "signin" | "ready">("starting");
  let identity = $state<Identity | null>(null);
  let dev = $state(false);
  let signinError = $state("");
  let signinValue = $state("");

  let place = $state<Place>("catalog");
  let selection = $state<Selection | undefined>();
  let inspector = $state(true);
  let paletteOpen = $state(false);
  let connectOpen = $state(false);
  let versionsRequested = $state(0);
  let known = $state<Known[]>([]);
  let rootCount = $state<number | null>(null);
  let copiedLine = $state(false);

  // ── Session ──────────────────────────────────────────────────────────────
  async function start() {
    try {
      identity = await get<Identity>("/auth/context");
      dev = identity.principal.auth_method === "none";
      phase = "ready";
      route();
    } catch (e) {
      const err = e as ApiError;
      if (err.status !== 401) signinError = err.message;
      phase = "signin";
    }
  }
  whenUnauthorized(() => {
    identity = null;
    if (phase === "ready") signinError = "Your credential was not accepted any more. Sign in again.";
    phase = "signin";
  });
  $effect(() => {
    void start();
  });

  async function signIn(e: SubmitEvent) {
    e.preventDefault();
    if (!signinValue.trim()) return;
    remember(signinValue);
    signinValue = "";
    signinError = "";
    try {
      identity = await get<Identity>("/auth/context");
      dev = false;
      phase = "ready";
      route();
    } catch (err) {
      forget();
      signinError = (err as ApiError).message;
    }
  }

  function signOut() {
    forget();
    indexed = false;
    identity = null;
    selection = undefined;
    known = [];
    phase = "signin";
  }

  // ── Routing: #/catalog[/table|view/<ns>/<name>] · #/policies[/versions] · #/you ──
  function route() {
    const [, p, kind, ns, name] = location.hash.split("/");
    if (p === "policies") {
      place = "policies";
      if (kind === "versions") versionsRequested++;
    } else if (p === "you") place = "you";
    else {
      place = "catalog";
      if ((kind === "table" || kind === "view") && ns && name) {
        const namespace = decodeURIComponent(ns).split("\u001f");
        selection = { kind, namespace, name: decodeURIComponent(name) };
      }
    }
  }
  function go(hash: string) {
    if (location.hash === hash) route();
    else location.hash = hash;
  }
  const select = (s: Selection) => go(`#/catalog/${s.kind}/${nsPath(s.namespace)}/${encodeURIComponent(s.name)}`);

  function addKnown(items: Known[]) {
    const seen = new Set(known.map((k) => `${k.kind}:${ident(k.namespace, k.name)}`));
    known = [...known, ...items.filter((k) => !seen.has(`${k.kind}:${ident(k.namespace, k.name)}`))];
  }

  // ⌘K searches the whole catalog, not just what the sidebar has opened: the first open walks it once,
  // breadth-first and bounded, through the same listings the sidebar uses.
  let indexed = false;
  async function indexCatalog() {
    if (indexed) return;
    indexed = true;
    try {
      const queue = await listNamespaces();
      for (let budget = 200; queue.length && budget > 0; budget--) {
        const ns = queue.shift()!;
        const [children, tables, views] = await Promise.all([
          listNamespaces(ns).catch(() => [] as string[][]),
          listTables(ns).catch(() => [] as Ident[]),
          listViews(ns).catch(() => [] as Ident[]),
        ]);
        queue.push(...children);
        addKnown([
          ...tables.map((t) => ({ kind: "table" as const, namespace: t.namespace, name: t.name })),
          ...views.map((v) => ({ kind: "view" as const, namespace: v.namespace, name: v.name })),
        ]);
      }
    } catch {
      indexed = false;
    }
  }
  $effect(() => {
    if (paletteOpen) void indexCatalog();
  });

  // ── Commands ─────────────────────────────────────────────────────────────
  const commands = $derived<Command[]>([
    { id: "p-catalog", title: "Catalog", hint: "⌘1", icon: "catalog", run: () => go("#/catalog") },
    { id: "p-policies", title: "Policies", hint: "⌘2", icon: "policy", run: () => go("#/policies") },
    { id: "p-versions", title: "Policy versions", icon: "versions", run: () => go("#/policies/versions") },
    { id: "p-you", title: "You", hint: "⌘3", icon: "person", run: () => go("#/you") },
    { id: "a-connect", title: "Connect a client", icon: "plug", run: () => (connectOpen = true) },
    ...(place === "catalog"
      ? [{ id: "a-inspector", title: inspector ? "Hide inspector" : "Show inspector", hint: "⌘I", icon: "inspector", run: () => (inspector = !inspector) }]
      : []),
    ...(dev ? [] : [{ id: "a-signout", title: "Sign out", icon: "signout", run: signOut }]),
    ...known
      .filter((k) => k.kind !== "namespace")
      .map((k) => ({
        id: `${k.kind}-${ident(k.namespace, k.name)}`,
        title: k.name!,
        hint: ident(k.namespace),
        terms: ident(k.namespace, k.name),
        icon: k.kind,
        run: () => select({ kind: k.kind as "table" | "view", namespace: k.namespace, name: k.name! }),
      })),
  ]);

  function keys(e: KeyboardEvent) {
    if (phase !== "ready") return;
    const mod = e.metaKey || e.ctrlKey;
    if (!mod) return;
    const k = e.key.toLowerCase();
    if (k === "k") {
      e.preventDefault();
      paletteOpen = !paletteOpen;
    } else if (k === "1" || k === "2" || k === "3") {
      e.preventDefault();
      go(k === "1" ? "#/catalog" : k === "2" ? "#/policies" : "#/you");
    } else if (k === "i" && place === "catalog") {
      e.preventDefault();
      inspector = !inspector;
    }
  }

  const title = $derived(
    place === "policies" ? "Policies" : place === "you" ? "You" : selection ? ident(selection.namespace, selection.name) : "Catalog",
  );
  const createLine = `catalog.create_namespace("analytics")`;
</script>

<svelte:window onhashchange={route} onkeydown={keys} />

{#if phase === "starting"}
  <div class="splash" aria-busy="true"><Symbol name="catalog" size={40} weight={1.2} /></div>
{:else if phase === "signin"}
  <main class="signin-page">
    <div class="mark" aria-hidden="true"><Symbol name="catalog" size={34} weight={1.5} /></div>
    <h1>Rustberg</h1>
    <p class="tagline">Sign in to see what you may see.</p>
    <form onsubmit={signIn} class="signin card">
      <label for="credential" class="sr-only">API key or bearer token</label>
      <input
        id="credential"
        type="password"
        bind:value={signinValue}
        placeholder="API key or bearer token"
        autocomplete="off"
        spellcheck="false"
      />
      <button class="btn primary large" type="submit" disabled={!signinValue.trim()}>Sign in</button>
      {#if signinError}<p class="error" role="alert"><Symbol name="warning" size={14} />{signinError}</p>{/if}
    </form>
    <p class="fine">
      Kept in this tab only — never in a cookie or a URL — and gone when the tab closes.<br />
      No key? An administrator creates one with <code>rustberg generate-key</code>.
    </p>
  </main>
{:else}
  <div class="shell">
    <aside class="sidebar glass">
      <div class="brand"><Symbol name="catalog" size={18} /><span>Rustberg</span></div>
      <nav aria-label="Places">
        <ul class="places">
          {#each [["catalog", "Catalog", "catalog", "⌘1"], ["policies", "Policies", "policy", "⌘2"], ["you", "You", "person", "⌘3"]] as [id, label, icon, hint] (id)}
            <li>
              <button class:on={place === id} aria-current={place === id ? "page" : undefined} onclick={() => go(`#/${id}`)}>
                <Symbol name={icon!} size={16} /><span>{label}</span><span class="hint">{hint}</span>
              </button>
            </li>
          {/each}
        </ul>
      </nav>
      <div class="outline">
        <Outline selected={selection} onselect={select} onknown={addKnown} onroots={(n) => (rootCount = n)} />
      </div>
    </aside>

    <div class="main">
      <header class="toolbar glass">
        <h2 class="where">{title}</h2>
        <button class="btn find" onclick={() => (paletteOpen = true)} aria-label="Go to (⌘K)">
          <Symbol name="search" size={14} /><span>Go to…</span><kbd>⌘K</kbd>
        </button>
        {#if dev}
          <span class="chip dev" title="Authentication is disabled on this server"><Symbol name="warning" size={13} />Development mode — no authentication</span>
        {:else if identity}
          <button class="chip" onclick={() => go("#/you")} title="Everything here is what this identity may see">
            <Symbol name="person" size={13} />
            <span>Viewing as <strong>{identity.principal.name || identity.principal.id}</strong></span>
            <span class="muted tenant">· {identity.principal.tenant_id}</span>
            {#if identity.principal.roles.length}<span class="muted">· {identity.principal.roles.join(", ")}</span>{/if}
          </button>
        {/if}
        {#if place === "catalog" && selection}
          <button class="btn plain icon" class:on={inspector} aria-pressed={inspector} aria-label="Inspector (⌘I)" onclick={() => (inspector = !inspector)}><Symbol name="inspector" size={16} /></button>
        {/if}
      </header>

      <main class="content">
        {#if place === "catalog"}
          {#if selection}
            <Catalog {selection} {inspector} />
          {:else}
            <div class="welcome">
              <Symbol name="catalog" size={44} weight={1.2} />
              {#if rootCount === 0}
                <h1>An empty catalog</h1>
                <p class="muted">Engines create namespaces and tables; this console shows them and who may see what. Create the first one from PyIceberg:</p>
                <button class="line mono" onclick={async () => { copiedLine = await copy(createLine); setTimeout(() => (copiedLine = false), 1600); }}>
                  {createLine}<Symbol name={copiedLine ? "check" : "copy"} size={13} />
                </button>
                <button class="btn" onclick={() => (connectOpen = true)}><Symbol name="plug" size={14} />Connect a client…</button>
              {:else}
                <h1>Pick a table</h1>
                <p class="muted">Choose a table or view in the sidebar, or press <kbd>⌘K</kbd> and type its name. What it shows is what you may see.</p>
              {/if}
            </div>
          {/if}
        {:else if place === "policies"}
          <Policies {versionsRequested} me={identity?.principal.id ?? ""} />
        {:else}
          <You {identity} {dev} onconnect={() => (connectOpen = true)} onsignout={signOut} />
        {/if}
      </main>
    </div>
  </div>

  {#if paletteOpen}<Palette {commands} onclose={() => (paletteOpen = false)} />{/if}
  {#if connectOpen}<Connect onclose={() => (connectOpen = false)} />{/if}
{/if}

<style>
  .splash {
    height: 100%;
    display: grid;
    place-items: center;
    color: var(--faint);
    background:
      radial-gradient(1200px 600px at 20% -10%, var(--accent-soft), transparent 60%),
      var(--bg);
  }
  .signin-page {
    height: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: var(--s5) var(--s5) 12vh;
    background:
      radial-gradient(900px 500px at 50% -10%, var(--accent-soft), transparent 70%),
      var(--bg);
  }
  .mark {
    width: 72px;
    height: 72px;
    border-radius: 18px;
    display: grid;
    place-items: center;
    color: #fff;
    background: linear-gradient(180deg, #5ea2ff, var(--accent));
    box-shadow: 0 10px 30px rgba(0, 122, 255, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.35);
    margin-bottom: var(--s3);
  }
  .signin-page h1 {
    margin: 0;
    font: 700 26px/1.2 var(--display);
  }
  .tagline {
    margin: 0 0 var(--s4);
    color: var(--muted);
    font-size: 15px;
  }
  .signin {
    width: min(380px, 100%);
    display: grid;
    grid-template-columns: 1fr auto;
    gap: var(--s2);
    padding: var(--s3);
  }
  .signin input {
    font: 13px var(--mono);
    padding: 0 10px;
    height: 34px;
  }
  .signin .error {
    grid-column: 1 / -1;
    margin: 0;
    font-size: 12px;
  }
  .fine code {
    white-space: nowrap;
  }
  .fine {
    margin: var(--s4) 0 0;
    text-align: center;
    font-size: 12px;
    color: var(--muted);
    max-width: 44ch;
  }
  .error {
    display: flex;
    gap: 6px;
    align-items: center;
    color: var(--denied);
  }
  .shell {
    display: grid;
    grid-template-columns: 248px minmax(0, 1fr);
    height: 100%;
  }
  .sidebar {
    display: flex;
    flex-direction: column;
    border-right: 0.5px solid var(--separator);
    min-height: 0;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 16px 16px 10px;
    font: 600 15px/1 var(--display);
    color: var(--accent-ink);
  }
  .brand span {
    color: var(--text);
  }
  .places {
    list-style: none;
    margin: 0;
    padding: 0 8px;
  }
  .places button {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    height: 30px;
    padding: 0 10px;
    border: none;
    border-radius: var(--r-sm);
    background: none;
    text-align: left;
    color: var(--text);
  }
  .places button:hover {
    background: var(--fill);
  }
  .places button.on {
    background: var(--fill-2);
    font-weight: 600;
  }
  .places button :global(svg) {
    color: var(--accent-ink);
  }
  .places span:nth-child(2) {
    flex: 1;
  }
  .hint {
    font-size: 11px;
    color: var(--muted);
  }
  .outline {
    flex: 1;
    overflow: auto;
    padding-bottom: var(--s4);
  }
  .main {
    display: flex;
    flex-direction: column;
    min-width: 0;
    min-height: 0;
  }
  .toolbar {
    display: flex;
    align-items: center;
    gap: var(--s3);
    height: 52px;
    padding: 0 var(--s4) 0 var(--s5);
    border-bottom: 0.5px solid var(--separator);
    position: relative;
    z-index: 5;
  }
  .where {
    flex: 1;
    margin: 0;
    font: 600 14px/1 var(--display);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .find {
    color: var(--muted);
    min-width: 180px;
  }
  .find span {
    flex: 1;
    text-align: left;
  }
  kbd {
    font: 11px var(--font);
    color: var(--muted);
    border: 0.5px solid var(--separator);
    border-radius: 4px;
    padding: 0 4px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 420px;
    height: 28px;
    padding: 0 12px;
    border-radius: 999px;
    border: 0.5px solid var(--separator);
    background: var(--surface);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 12px;
  }
  .chip.dev {
    color: var(--restricted);
    background: var(--restricted-soft);
    border-color: transparent;
  }
  .icon {
    padding: 0 6px;
  }
  .icon.on {
    color: var(--accent);
  }
  .content {
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }
  .welcome {
    height: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--s3);
    text-align: center;
    padding: var(--s6);
    color: var(--muted);
  }
  .welcome h1 {
    margin: 0;
    font: 700 22px/1.2 var(--display);
    color: var(--text);
  }
  .welcome p {
    margin: 0;
    max-width: 48ch;
  }
  .line {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    border-radius: var(--r);
    border: 0.5px solid var(--separator);
    background: var(--surface);
    color: var(--text);
  }
  @media (max-width: 1100px) {
    .shell {
      grid-template-columns: 220px minmax(0, 1fr);
    }
    .chip .tenant {
      display: none;
    }
  }
  @media (max-width: 760px) {
    .shell {
      grid-template-columns: minmax(0, 1fr);
      grid-template-rows: auto minmax(0, 1fr);
    }
    .sidebar {
      max-height: 40vh;
      border-right: none;
      border-bottom: 0.5px solid var(--separator);
    }
  }
</style>
