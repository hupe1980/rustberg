<script lang="ts">
  // One table or view: what it holds in the content area, its metadata in the inspector. "What you can
  // see" restates what the server published for this caller — this console computes nothing about it.
  import Symbol from "../components/Symbol.svelte";
  import CodeView from "../components/CodeView.svelte";
  import type { Selection } from "../components/Outline.svelte";
  import { ApiError, loadTable, loadView, type LoadTable, type LoadView, type Schema } from "../lib/api";
  import { ago, ident, typeName, when } from "../lib/format";
  import { describe } from "../lib/predicate";
  import { copy } from "../lib/clipboard";

  let { selection, inspector }: { selection: Selection; inspector: boolean } = $props();

  let table = $state<LoadTable | null>(null);
  let view = $state<LoadView | null>(null);
  let error = $state<ApiError | null>(null);
  let loading = $state(true);
  let allSnapshots = $state(false);

  $effect(() => {
    const s = selection;
    table = null;
    view = null;
    error = null;
    loading = true;
    allSnapshots = false;
    const load = s.kind === "table" ? loadTable(s.namespace, s.name).then((t) => (table = t)) : loadView(s.namespace, s.name).then((v) => (view = v));
    load.catch((e) => (error = e)).finally(() => (loading = false));
  });

  const schema = $derived.by((): Schema | undefined => {
    if (table) return table.metadata.schemas.find((x) => x["schema-id"] === table!.metadata["current-schema-id"]);
    if (view) {
      const v = view.metadata.versions.find((x) => x["version-id"] === view!.metadata["current-version-id"]);
      return view.metadata.schemas.find((x) => x["schema-id"] === v?.["schema-id"]);
    }
    return undefined;
  });
  const names = $derived(new Map((schema?.fields ?? []).map((f) => [f.id, f.name])));

  const restrictions = $derived(table?.["read-restrictions"]);
  const masked = $derived(new Set((restrictions?.["required-column-projections"] ?? []).map((p) => p["field-id"])));
  const filter = $derived(restrictions?.["required-row-filter"]);
  const serverPlanning = $derived(table?.config?.["scan-planning-mode"] === "server");
  const restricted = $derived(Boolean(restrictions) || serverPlanning);

  const snapshots = $derived(
    [...(table?.metadata.snapshots ?? [])].sort((a, b) => b["timestamp-ms"] - a["timestamp-ms"]),
  );
  const sql = $derived.by(() => {
    if (!view) return "";
    const v = view.metadata.versions.find((x) => x["version-id"] === view!.metadata["current-version-id"]);
    return v?.representations.find((r) => r.type === "sql")?.sql ?? "";
  });
  const properties = $derived(Object.entries((table?.metadata.properties ?? view?.metadata.properties) ?? {}).sort());
</script>

<div class="split" class:with-inspector={inspector}>
  <section class="content" aria-labelledby="object-title">
    <header class="title">
      <Symbol name={selection.kind} size={28} weight={1.4} />
      <div>
        <h1 id="object-title">{selection.name}</h1>
        <p class="muted mono">{ident(selection.namespace)}</p>
      </div>
    </header>

    {#if loading}
      <div class="card"><span class="skeleton" style="width: 40%"></span><br /><span class="skeleton" style="width: 70%"></span></div>
    {:else if error}
      <div class="card notice">
        <Symbol name={error.status === 404 || error.status === 403 ? "lock" : "warning"} size={20} />
        <div>
          <strong>{error.status === 404 || error.status === 403 ? "Not visible to you" : "Could not load this"}</strong>
          <p class="muted">{error.message}</p>
        </div>
      </div>
    {:else}
      {#if table}
        <div class="card see" class:restricted aria-labelledby="see-title">
          <h2 id="see-title" class="section-title">What you can see</h2>
          {#if restricted}
            <p class="lede">
              <span class="state restricted"><Symbol name="shield" size={13} />Restricted</span>
              This table is narrowed for you. The server withholds storage credentials and plans your reads, so you
              receive only the files your filter selects.
            </p>
            <dl>
              <dt><Symbol name="filter" size={14} />Rows</dt>
              <dd class="mono">{filter === undefined ? "all rows" : describe(filter, names)}</dd>
              <dt><Symbol name="eye-slash" size={14} />Masked</dt>
              <dd>
                {#if masked.size}
                  {#each [...masked] as id (id)}<code class="pill">{names.get(id) ?? `#${id}`}</code>{/each}
                {:else}<span class="muted">no columns</span>{/if}
              </dd>
              <dt><Symbol name="catalog" size={14} />Planning</dt>
              <dd>{serverPlanning ? "Server-side — required" : "Client-side allowed"}</dd>
            </dl>
          {:else}
            <p class="lede">
              <span class="state allowed"><Symbol name="shield-check" size={13} />Unrestricted</span>
              No row filter or mask applies to you on this table.
            </p>
          {/if}
        </div>
      {/if}

      {#if view && sql}
        <h2 class="section-title">Definition</h2>
        <CodeView text={sql} cedar={false} label="View SQL" />
      {/if}

      <h2 class="section-title">Schema</h2>
      <div class="card flush">
        <table class="grid">
          <thead><tr><th class="num">ID</th><th>Column</th><th>Type</th><th>Required</th></tr></thead>
          <tbody>
            {#each schema?.fields ?? [] as f (f.id)}
              <tr>
                <td class="num muted">{f.id}</td>
                <td>
                  <span class="mono">{f.name}</span>
                  {#if masked.has(f.id)}<span class="state restricted tiny"><Symbol name="eye-slash" size={11} />masked for you</span>{/if}
                  {#if f.doc}<div class="muted doc">{f.doc}</div>{/if}
                </td>
                <td class="mono">{typeName(f.type).replace(/, /g, ",\u00a0")}</td>
                <td>{f.required ? "Required" : "Optional"}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  {#if inspector && (table || view)}
    <aside class="inspector" aria-label="Inspector">
      <h2 class="section-title">Overview</h2>
      <dl class="facts">
        {#if table}<dt>Format</dt><dd>v{table.metadata["format-version"]}</dd>{/if}
        <dt>Location</dt>
        <dd class="mono path">
          {#each (table ?? view)!.metadata.location.split("/") as part, i (i)}{#if i}/<wbr />{/if}{part}{/each}
          <button class="btn plain icon" aria-label="Copy location" onclick={() => copy((table ?? view)!.metadata.location)}><Symbol name="copy" size={13} /></button>
        </dd>
        <dt>UUID</dt><dd class="mono uuid">{table ? table.metadata["table-uuid"] : view?.metadata["view-uuid"]}</dd>
      </dl>

      {#if table}
        <h2 class="section-title">Partitioning</h2>
        {#each [...table.metadata["partition-specs"]].reverse() as spec (spec["spec-id"])}
          <div class="spec" class:current={spec["spec-id"] === table.metadata["default-spec-id"]}>
            <div class="spec-head">
              <span>Spec {spec["spec-id"]}</span>
              {#if spec["spec-id"] === table.metadata["default-spec-id"]}<span class="tag">current</span>{/if}
            </div>
            {#if spec.fields.length}
              {#each spec.fields as f (f["field-id"])}
                <div class="mono small">{f.transform}({names.get(f["source-id"]) ?? `#${f["source-id"]}`})</div>
              {/each}
            {:else}<div class="muted small">Unpartitioned</div>{/if}
          </div>
        {/each}

        <h2 class="section-title">Snapshots</h2>
        {#if snapshots.length === 0}
          <p class="muted small">No snapshots — the table holds no data yet.</p>
        {:else}
          <ol class="snaps">
            {#each allSnapshots ? snapshots : snapshots.slice(0, 5) as s (s["snapshot-id"])}
              <li class:current={s["snapshot-id"] === table.metadata["current-snapshot-id"]}>
                <Symbol name="snapshot" size={14} />
                <div>
                  <div>{s.summary?.operation ?? "snapshot"} <span class="muted">· {ago(s["timestamp-ms"])}</span></div>
                  <div class="muted small mono" title={when(s["timestamp-ms"])}>{s["snapshot-id"]}</div>
                </div>
              </li>
            {/each}
          </ol>
          {#if snapshots.length > 5}
            <button class="btn plain" onclick={() => (allSnapshots = !allSnapshots)}>
              {allSnapshots ? "Show fewer" : `Show all ${snapshots.length}`}
            </button>
          {/if}
        {/if}
      {/if}

      {#if view}
        <h2 class="section-title">Versions</h2>
        <ol class="snaps">
          {#each [...view.metadata.versions].reverse() as v (v["version-id"])}
            <li class:current={v["version-id"] === view.metadata["current-version-id"]}>
              <Symbol name="versions" size={14} />
              <div>Version {v["version-id"]} <span class="muted">· {ago(v["timestamp-ms"])}</span></div>
            </li>
          {/each}
        </ol>
      {/if}

      <h2 class="section-title">Properties</h2>
      {#if properties.length}
        <dl class="facts">
          {#each properties as [k, v] (k)}<dt class="mono small">{k}</dt><dd class="mono small wrap">{v}</dd>{/each}
        </dl>
      {:else}<p class="muted small">None</p>{/if}
    </aside>
  {/if}
</div>

<style>
  .split {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    height: 100%;
  }
  .split.with-inspector {
    grid-template-columns: minmax(0, 1fr) 280px;
  }
  .content {
    overflow: auto;
    padding: var(--s5) var(--s6) var(--s6);
  }
  .content > :global(.section-title) {
    margin-top: var(--s5);
  }
  .title {
    display: flex;
    gap: var(--s3);
    align-items: center;
    color: var(--accent-ink);
    margin-bottom: var(--s4);
  }
  h1 {
    margin: 0;
    font: 700 22px/1.2 var(--display);
    color: var(--text);
  }
  .title p {
    margin: 2px 0 0;
  }
  .notice {
    display: flex;
    gap: var(--s3);
    align-items: flex-start;
  }
  .notice p {
    margin: 4px 0 0;
  }
  .see .lede {
    margin: 0;
    display: flex;
    gap: var(--s2);
    align-items: baseline;
    flex-wrap: wrap;
    color: var(--text-2);
  }
  .see.restricted {
    box-shadow: var(--shadow), inset 3px 0 0 var(--restricted);
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 8px 16px;
    margin: var(--s3) 0 0;
  }
  dt {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--muted);
  }
  dd {
    margin: 0;
  }
  .pill {
    display: inline-block;
    padding: 1px 6px;
    margin: 0 4px 2px 0;
    border-radius: var(--r-sm);
    background: var(--restricted-soft);
    color: var(--restricted);
  }
  .tiny {
    font-size: 10px;
    padding: 0 6px 0 4px;
    margin-left: 6px;
    white-space: nowrap;
    vertical-align: 1px;
  }

  .flush {
    padding: 0;
    overflow: hidden;
  }
  .grid {
    width: 100%;
    border-collapse: collapse;
  }
  .grid th {
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    color: var(--muted);
    padding: 8px 12px;
    border-bottom: 0.5px solid var(--separator);
  }
  .grid td {
    padding: 7px 12px;
    border-bottom: 0.5px solid var(--separator);
    vertical-align: top;
  }
  .grid tr:last-child td {
    border-bottom: none;
  }
  .doc {
    font-size: 12px;
  }
  .inspector {
    overflow: auto;
    padding: var(--s5) var(--s4);
    border-left: 0.5px solid var(--separator);
    background: var(--surface-2);
  }
  .inspector .section-title {
    margin-top: var(--s5);
  }
  .inspector .section-title:first-child {
    margin-top: 0;
  }
  .facts {
    grid-template-columns: 1fr;
    gap: 2px;
    margin: 0;
  }
  .facts dt {
    margin-top: 8px;
    font-size: 11px;
  }
  .wrap {
    word-break: break-all;
  }
  .path {
    overflow-wrap: anywhere;
  }
  .uuid {
    font-size: 10.5px;
    white-space: nowrap;
  }
  .small {
    font-size: 11px;
  }
  .icon {
    height: 20px;
    padding: 0 4px;
    vertical-align: middle;
  }
  .spec {
    padding: 8px 10px;
    border-radius: var(--r);
    background: var(--surface);
    margin-bottom: 6px;
    border: 0.5px solid var(--separator);
  }
  .spec.current {
    border-color: var(--accent);
  }
  .spec-head {
    display: flex;
    justify-content: space-between;
    font-weight: 600;
    margin-bottom: 4px;
  }
  .tag {
    font-size: 10px;
    font-weight: 600;
    color: var(--accent-ink);
    background: var(--accent-soft);
    border-radius: 999px;
    padding: 1px 7px;
  }
  .snaps {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .snaps li {
    display: flex;
    gap: 8px;
    padding: 6px 0;
    color: var(--muted);
    border-bottom: 0.5px solid var(--separator);
  }
  .snaps li div {
    color: var(--text);
  }
  .snaps li.current {
    color: var(--accent-ink);
  }
  @media (max-width: 760px) {
    .split.with-inspector {
      grid-template-columns: minmax(0, 1fr);
    }
    .inspector {
      border-left: none;
      border-top: 0.5px solid var(--separator);
    }
  }
</style>
