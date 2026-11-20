<script lang="ts">
  // One table or view: what it holds in the content area, its metadata in the inspector. "What you can
  // see" restates what the server published for this caller — this console computes nothing about it.
  import Symbol from "../components/Symbol.svelte";
  import CodeView from "../components/CodeView.svelte";
  import type { Selection } from "../components/Outline.svelte";
  import { ApiError, explain, loadTableGraded, tableAccess, type AccessRow, loadView, type Explain, type LoadTable, type LoadView, type Schema, type Subject } from "../lib/api";
  import { strength, type Grade } from "../lib/grade";
  import { ago, ident, typeName, when } from "../lib/format";
  import { describe } from "../lib/predicate";
  import { copy } from "../lib/clipboard";

  let {
    selection,
    inspector,
    viewAs = null,
    onviewas,
  }: { selection: Selection; inspector: boolean; viewAs?: Subject | null; onviewas?: (s: Subject) => void } = $props();

  let table = $state<LoadTable | null>(null);
  let view = $state<LoadView | null>(null);
  let error = $state<ApiError | null>(null);
  let ownGrade = $state<Grade | undefined>();
  let preview = $state<Explain | null>(null);
  let previewError = $state<ApiError | null>(null);
  let copiedReference = $state(false);
  // Who may read this table, and in what form — shown only to someone who may read the policy set.
  let access = $state<AccessRow[] | null>(null);
  $effect(() => {
    const s = selection;
    access = null;
    if (s.kind !== "table") return;
    tableAccess(s.namespace, s.name)
      .then((a) => (access = a.rows))
      .catch(() => (access = null));
  });
  const accessWords: Record<AccessRow["access"], string> = {
    everything: "everything",
    filtered: "filtered rows",
    masked: "masked columns",
    "filtered-and-masked": "filtered, masked",
    nothing: "nothing",
  };
  const label = (r: AccessRow) =>
    r.principal.kind === "group" ? r.principal.roles[0]! : r.principal.kind === "anyone" ? "no group" : r.principal.id;
  const asSubject = (r: AccessRow): Subject => ({
    id: r.principal.kind === "group" ? `a member of ${r.principal.roles[0]}` : r.principal.id,
    kind: r.principal.kind === "api_key" ? "api_key" : "user",
    roles: r.principal.roles,
  });
  let loading = $state(true);
  let allSnapshots = $state(false);

  $effect(() => {
    const s = selection;
    table = null;
    view = null;
    error = null;
    loading = true;
    allSnapshots = false;
    ownGrade = undefined;
    const load =
      s.kind === "table"
        ? loadTableGraded(s.namespace, s.name).then((r) => {
            table = r.table;
            ownGrade = r.grade;
          })
        : loadView(s.namespace, s.name).then((v) => (view = v));
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

  // A preview is the server's what-if about another principal; the console renders it and computes nothing.
  $effect(() => {
    const s = selection;
    const who = viewAs;
    preview = null;
    previewError = null;
    if (!who || s.kind !== "table") return;
    explain(s.namespace, s.name, who)
      .then((p) => (preview = p))
      .catch((e) => (previewError = e));
  });

  const previewing = $derived(Boolean(viewAs) && selection.kind === "table");
  const restrictions = $derived(previewing ? preview?.["read-restrictions"] : table?.["read-restrictions"]);
  const masked = $derived(new Set((restrictions?.["required-column-projections"] ?? []).map((p) => p["field-id"])));
  const filter = $derived(restrictions?.["required-row-filter"]);
  const serverPlanning = $derived(previewing ? Boolean(restrictions) : table?.config?.["scan-planning-mode"] === "server");
  const restricted = $derived(Boolean(restrictions) || serverPlanning);
  const grade = $derived.by((): Grade | undefined => {
    if (!previewing) return ownGrade;
    const e = preview?.enforcement;
    return e ? { grade: e.grade, columns: e.columns ?? [], masked: e.masked } : undefined;
  });
  const told = $derived(grade && grade.grade !== "none" ? strength(grade) : undefined);
  const remedy = $derived(previewing ? preview?.enforcement?.remedy : undefined);

  async function copyReference(reference: string) {
    copiedReference = await copy(reference);
    setTimeout(() => (copiedReference = false), 1600);
  }

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
          {#if error.reference}
            <p class="reference small">
              <span class="muted">Reference</span>
              <button class="ref mono" title="Copy — an administrator finds the decision in the audit trail by it" onclick={() => copyReference(error!.reference!)}>
                {error.reference}<Symbol name={copiedReference ? "check" : "copy"} size={12} />
              </button>
            </p>
          {/if}
        </div>
      </div>
    {:else}
      {#if table}
        <div class="card see" class:restricted class:previewing aria-labelledby="see-title">
          <h2 id="see-title" class="section-title">
            {#if previewing}What <span class="who">{viewAs!.id}</span> would see{:else}What you can see{/if}
          </h2>
          {#if previewing && previewError}
            <p class="lede">
              <span class="state denied"><Symbol name="lock" size={13} />Preview unavailable</span>
              {previewError.status === 403 || previewError.status === 501
                ? "Previewing another person's view needs permission to read the policy set."
                : previewError.message}
            </p>
          {:else if previewing && !preview}
            <span class="skeleton" style="width: 60%"></span>
          {:else if previewing && preview?.decision === "deny"}
            <p class="lede">
              <span class="state denied"><Symbol name="lock" size={13} />Denied</span>
              {viewAs!.id} cannot read this table.
              {preview["matched-policies"].length ? "A forbid matched." : "No policy permits it, so it is denied by default."}
            </p>
            {#if preview["matched-policies"].length}
              <dl><dt><Symbol name="policy" size={14} />Forbidden by</dt><dd>{#each preview["matched-policies"] as id (id)}<code class="pill">{id}</code>{/each}</dd></dl>
            {/if}
          {:else if previewing && preview?.refused}
            <p class="lede">
              <span class="state denied"><Symbol name="warning" size={13} />Refused</span>
              Permitted, but loading would be refused: {preview.refused}
            </p>
          {:else if restricted}
            <p class="lede">
              <span class="state restricted"><Symbol name="shield" size={13} />Restricted</span>
              This table is narrowed for {previewing ? "them" : "you"}. The server withholds storage credentials and plans
              reads itself, handing over only the files the filter selects.
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
              {#if told && grade}
                <dt><Symbol name={grade.grade === "architectural" ? "shield-check" : "shield"} size={14} />Strength</dt>
                <dd class="strength" class:strong={grade.grade === "architectural"}>
                  <strong>{told.title}</strong>
                  <span class="muted">{told.detail}</span>
                </dd>
              {/if}
              {#if remedy}
                <dt><Symbol name="info" size={14} />To strengthen</dt>
                <dd class="muted remedy">{remedy}</dd>
              {/if}
              {#if previewing && preview?.["matched-policies"].length}
                <dt><Symbol name="policy" size={14} />Granted by</dt>
                <dd>{#each preview["matched-policies"] as id (id)}<code class="pill">{id}</code>{/each}</dd>
              {/if}
            </dl>
          {:else}
            <p class="lede">
              <span class="state allowed"><Symbol name="shield-check" size={13} />Unrestricted</span>
              No row filter or mask applies to {previewing ? "them" : "you"} on this table.
            </p>
          {/if}
          {#if previewing && preview}
            <p class="fine muted small">{preview.context} Answered by the server; nothing was read as {viewAs!.id}.</p>
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
      {#if access?.length}
        <h2 class="section-title">Who can read this</h2>
        <ul class="access" aria-label="Who can read this table, and in what form">
          {#each access as r (r.principal.kind + r.principal.id)}
            <li>
              <Symbol name={r.principal.kind === "group" ? "person" : r.principal.kind === "api_key" ? "key" : "person"} size={12} />
              <span class="name" title={r["matched-policies"].join(", ")}>{label(r)}</span>
              <span class="state tiny" class:allowed={r.access === "everything"} class:restricted={r.access !== "everything" && r.access !== "nothing"} class:denied={r.access === "nothing"}>
                {accessWords[r.access]}{#if r.grade?.grade === "cooperative"}{" · cooperative"}{/if}
              </span>
              {#if onviewas && r.access !== "nothing"}
                <button class="btn plain icon" aria-label={`View as ${label(r)}`} title="View as" onclick={() => onviewas!(asSubject(r))}><Symbol name="eye" size={12} /></button>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
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
  .access {
    list-style: none;
    margin: 0 0 var(--s4);
    padding: 0;
    display: grid;
    gap: 6px;
  }
  .access li {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
  }
  .access .name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .see.previewing {
    box-shadow: var(--shadow), inset 3px 0 0 var(--accent);
  }
  .see.previewing.restricted {
    box-shadow: var(--shadow), inset 3px 0 0 var(--accent), inset 6px 0 0 var(--restricted);
  }
  .who {
    color: var(--accent-ink);
    text-transform: none;
    letter-spacing: 0;
  }
  .strength {
    display: grid;
    gap: 2px;
  }
  .strength strong {
    color: var(--restricted);
  }
  .strength.strong strong {
    color: var(--allowed);
  }
  .remedy {
    font-size: 13px;
    line-height: 1.45;
  }
  .fine {
    margin: var(--s3) 0 0;
  }
  .reference {
    display: flex;
    gap: var(--s2);
    align-items: center;
    margin-top: var(--s2);
  }
  .ref {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    padding: 2px 8px;
    border: 1px solid var(--line, var(--faint));
    border-radius: var(--r-sm);
    background: transparent;
    color: var(--text-2);
    cursor: copy;
  }
  .ref:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
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
