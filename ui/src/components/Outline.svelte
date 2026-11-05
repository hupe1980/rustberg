<script lang="ts" module>
  export type Selection = { kind: "table" | "view"; namespace: string[]; name: string };
  export type Known = { kind: "namespace" | "table" | "view"; namespace: string[]; name?: string };
</script>

<script lang="ts">
  // The catalog as a Finder-style outline: namespaces disclose their children, tables and views on first
  // open. Arrow keys move, → opens, ← closes, Enter selects.
  import Symbol from "./Symbol.svelte";
  import { listNamespaces, listTables, listViews, type Ident } from "../lib/api";

  type Node = {
    ns: string[];
    open: boolean;
    loaded: boolean;
    loading: boolean;
    children: string[][];
    tables: Ident[];
    views: Ident[];
    error?: string;
  };

  let {
    selected,
    onselect,
    onknown,
    onroots = () => {},
  }: {
    selected?: Selection;
    onselect: (s: Selection) => void;
    onknown: (items: Known[]) => void;
    onroots?: (count: number) => void;
  } = $props();

  let roots = $state<string[][] | null>(null);
  let rootError = $state<string | null>(null);
  let nodes = $state<Record<string, Node>>({});
  let tree: HTMLElement | undefined = $state();

  const key = (ns: string[]) => ns.join("\u001f");

  $effect(() => {
    listNamespaces()
      .then((ns) => {
        roots = ns;
        onroots(ns.length);
        onknown(ns.map((n) => ({ kind: "namespace", namespace: n })));
      })
      .catch((e) => (rootError = e.message));
  });

  // Whatever is selected — from a click, ⌘K or a link — is visible here: its namespaces are opened.
  $effect(() => {
    const ns = selected?.namespace;
    if (roots && ns) void reveal(ns);
  });

  async function toggle(ns: string[], open?: boolean) {
    const k = key(ns);
    nodes[k] ??= { ns, open: false, loaded: false, loading: false, children: [], tables: [], views: [] };
    // Read back through the state: `??=` yields the plain object, and mutating that would bypass reactivity.
    const node = nodes[k]!;
    node.open = open ?? !node.open;
    if (node.open && !node.loaded && !node.loading) {
      node.loading = true;
      try {
        const [children, tables, views] = await Promise.all([
          listNamespaces(ns),
          listTables(ns),
          listViews(ns).catch(() => [] as Ident[]),
        ]);
        node.children = children;
        node.tables = tables;
        node.views = views;
        node.loaded = true;
        onknown([
          ...children.map((c) => ({ kind: "namespace" as const, namespace: c })),
          ...tables.map((t) => ({ kind: "table" as const, namespace: t.namespace, name: t.name })),
          ...views.map((v) => ({ kind: "view" as const, namespace: v.namespace, name: v.name })),
        ]);
      } catch (e) {
        node.error = (e as Error).message;
      } finally {
        node.loading = false;
      }
    }
  }

  export async function reveal(ns: string[]) {
    for (let i = 1; i <= ns.length; i++) await toggle(ns.slice(0, i), true);
  }

  function rows(): HTMLElement[] {
    return Array.from(tree?.querySelectorAll<HTMLElement>("[data-row]") ?? []);
  }

  function nav(e: KeyboardEvent) {
    const all = rows();
    const at = all.indexOf(document.activeElement as HTMLElement);
    if (at < 0) return;
    const row = all[at]!;
    if (e.key === "ArrowDown") all[Math.min(all.length - 1, at + 1)]?.focus();
    else if (e.key === "ArrowUp") all[Math.max(0, at - 1)]?.focus();
    else if (e.key === "ArrowRight" && row.dataset.ns) void toggle(row.dataset.ns.split("\u001f"), true);
    else if (e.key === "ArrowLeft" && row.dataset.ns) void toggle(row.dataset.ns.split("\u001f"), false);
    else return;
    e.preventDefault();
  }

  const isSelected = (kind: string, i: Ident) =>
    selected?.kind === kind && selected.name === i.name && key(selected.namespace) === key(i.namespace);
</script>

{#snippet namespace(ns: string[], depth: number)}
  {@const node = nodes[key(ns)]}
  <li role="treeitem" aria-expanded={node?.open ?? false} aria-selected="false">
    <button
      class="row"
      data-row
      data-ns={key(ns)}
      style:--depth={depth}
      onclick={() => toggle(ns)}
    >
      <span class="disc" class:open={node?.open}><Symbol name="chevron-right" size={11} weight={2} /></span>
      <Symbol name="folder" size={15} />
      <span class="name">{ns[ns.length - 1]}</span>
    </button>
    {#if node?.open}
      <ul role="group">
        {#if node.loading}
          <li class="hint" style:--depth={depth + 1}><span class="skeleton" style="width: 60%"></span></li>
        {:else if node.error}
          <li class="hint error" style:--depth={depth + 1}>{node.error}</li>
        {:else}
          {#each node.children as child (key(child))}{@render namespace(child, depth + 1)}{/each}
          {#each node.tables as t (t.name)}
            <li role="treeitem" aria-selected={isSelected("table", t)}>
              <button
                class="row leaf"
                class:sel={isSelected("table", t)}
                data-row
                style:--depth={depth + 1}
                onclick={() => onselect({ kind: "table", namespace: t.namespace, name: t.name })}
              >
                <Symbol name="table" size={15} /><span class="name">{t.name}</span>
              </button>
            </li>
          {/each}
          {#each node.views as v (v.name)}
            <li role="treeitem" aria-selected={isSelected("view", v)}>
              <button
                class="row leaf"
                class:sel={isSelected("view", v)}
                data-row
                style:--depth={depth + 1}
                onclick={() => onselect({ kind: "view", namespace: v.namespace, name: v.name })}
              >
                <Symbol name="view" size={15} /><span class="name">{v.name}</span><span class="kind">view</span>
              </button>
            </li>
          {/each}
          {#if !node.children.length && !node.tables.length && !node.views.length}
            <li class="hint" style:--depth={depth + 1}>Empty</li>
          {/if}
        {/if}
      </ul>
    {/if}
  </li>
{/snippet}

<nav aria-label="Catalog">
  <h2 class="section-title">Catalog</h2>
  {#if rootError}
    <p class="hint error">{rootError}</p>
  {:else if roots === null}
    <p class="hint"><span class="skeleton" style="width: 70%"></span></p>
  {:else if roots.length === 0}
    <p class="hint">No namespaces yet.</p>
  {:else}
    <ul role="tree" aria-label="Namespaces, tables and views" bind:this={tree} onkeydown={nav}>
      {#each roots as ns (key(ns))}{@render namespace(ns, 0)}{/each}
    </ul>
  {/if}
</nav>

<style>
  nav {
    padding: 0 8px;
  }
  .section-title {
    padding: 0 8px;
    margin-top: var(--s4);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .row {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 26px;
    padding: 0 8px 0 calc(6px + var(--depth) * 14px);
    border: none;
    border-radius: var(--r-sm);
    background: none;
    text-align: left;
    color: var(--text);
  }
  .row:hover {
    background: var(--fill);
  }
  .row.sel {
    background: var(--accent);
    color: #fff;
  }
  .leaf {
    padding-left: calc(23px + var(--depth) * 14px);
  }
  .disc {
    display: inline-flex;
    color: var(--muted);
    transition: transform 140ms var(--ease);
  }
  .disc.open {
    transform: rotate(90deg);
  }
  .name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .kind {
    font-size: 10px;
    color: var(--muted);
  }
  .row.sel .kind {
    color: rgba(255, 255, 255, 0.8);
  }
  .hint {
    padding: 4px 8px 4px calc(23px + var(--depth, 0) * 14px);
    color: var(--muted);
    font-size: 12px;
    margin: 0;
  }
  .error {
    color: var(--denied);
  }
</style>
