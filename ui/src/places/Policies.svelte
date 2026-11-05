<script lang="ts">
  // The policy set as a document: Edit → Review (diff + note) → Save; a refusal keeps the draft.
  // Restore asks nothing — it is itself a revision, so Undo is the safety net.
  import Symbol from "../components/Symbol.svelte";
  import Sheet from "../components/Sheet.svelte";
  import CodeView from "../components/CodeView.svelte";
  import Diff from "../components/Diff.svelte";
  import { ApiError, call, get, type PolicyRevision, type RevisionSummary } from "../lib/api";
  import { ago, when } from "../lib/format";

  let { versionsRequested = 0, me = "" }: { versionsRequested?: number; me?: string } = $props();

  const by = (author: string) => (author === me ? "you" : /^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(author) ? `${author.slice(0, 8)}…` : author);

  let current = $state<PolicyRevision | null>(null);
  let phase = $state<"loading" | "ready" | "unadministered" | "error">("loading");
  let loadError = $state("");
  let readOnly = $state(false);

  let editing = $state(false);
  let draft = $state("");
  let reviewing = $state(false);
  let note = $state("");
  let saving = $state(false);
  let saveError = $state("");

  let versionsOpen = $state(false);
  let history = $state<RevisionSummary[]>([]);
  let picked = $state<PolicyRevision | null>(null);
  let toast = $state<{ text: string; undoTo?: number; icon?: "lock" | "warning" } | null>(null);

  async function load() {
    try {
      current = await get<PolicyRevision>("/management/v1/policies");
      phase = "ready";
    } catch (e) {
      const err = e as ApiError;
      if (err.status === 501) phase = "unadministered";
      else {
        phase = "error";
        loadError = err.message;
      }
    }
  }
  $effect(() => {
    void load();
  });
  $effect(() => {
    if (versionsRequested > 0) void openVersions();
  });

  function startEdit() {
    draft = current?.source ?? "";
    editing = true;
  }

  async function save() {
    saving = true;
    saveError = "";
    try {
      const previous = current!.sequence;
      current = (await call<PolicyRevision>("PUT", "/management/v1/policies", { source: draft, note: note || undefined })).data;
      reviewing = false;
      editing = false;
      note = "";
      toast = { text: `Installed as revision ${current.sequence}.`, undoTo: previous };
    } catch (e) {
      const err = e as ApiError;
      if (err.status === 403) readOnly = true;
      saveError = err.status === 403 ? "You may read this policy set but not change it." : err.message;
    } finally {
      saving = false;
    }
  }

  async function openVersions() {
    versionsOpen = true;
    picked = null;
    try {
      history = (await get<{ revisions: RevisionSummary[] }>("/management/v1/policies/history?limit=100")).revisions;
      const first = history.find((r) => r.sequence !== current?.sequence);
      if (first) await pick(first.sequence);
    } catch (e) {
      toast = { text: (e as ApiError).message, icon: "warning" };
    }
  }

  async function pick(sequence: number) {
    picked = await get<PolicyRevision>(`/management/v1/policies/revisions/${sequence}`);
  }

  async function restore(sequence: number, undo = false) {
    const previous = current!.sequence;
    try {
      current = (
        await call<PolicyRevision>("POST", "/management/v1/policies/rollback", {
          sequence,
          note: undo ? `Undo: back to revision ${sequence}` : undefined,
        })
      ).data;
      versionsOpen = false;
      toast = undo
        ? { text: `Back to the rules of revision ${sequence}.` }
        : { text: `Restored revision ${sequence} as revision ${current.sequence}.`, undoTo: previous };
    } catch (e) {
      const err = e as ApiError;
      if (err.status === 403) readOnly = true;
      toast =
        err.status === 403
          ? { text: "You may read this policy set but not change it.", icon: "lock" }
          : { text: err.message, icon: "warning" };
    }
  }

  $effect(() => {
    if (!toast) return;
    const t = setTimeout(() => (toast = null), 8000);
    return () => clearTimeout(t);
  });

  function key(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key === "s" && editing) {
      e.preventDefault();
      reviewing = true;
    }
  }
</script>

<svelte:window onkeydown={key} />

<section class="page" aria-labelledby="policies-title">
  <header class="head">
    <div>
      <h1 id="policies-title">Policies</h1>
      {#if current}
        <p class="muted">
          Revision <strong class="num">{current.sequence}</strong> · by <span title={current.author}>{by(current.author)}</span> ·
          <span title={when(current.created_at_ms)}>{ago(current.created_at_ms)}</span>
          {#if current.note}· “{current.note}”{/if}
          {#if current.latest_sequence !== current.sequence}
            · <span class="state restricted"><Symbol name="warning" size={11} />revision {current.latest_sequence} is newer and not yet in force here</span>
          {/if}
        </p>
      {/if}
    </div>
    {#if phase === "ready"}
      <div class="actions">
        {#if editing}
          <button class="btn" onclick={() => (editing = false)}>Cancel</button>
          <button class="btn primary" disabled={draft === current?.source} onclick={() => (reviewing = true)}>Review…</button>
        {:else}
          <button class="btn" onclick={openVersions}><Symbol name="versions" size={14} />Versions</button>
          {#if !readOnly}<button class="btn primary" onclick={startEdit}><Symbol name="pencil" size={14} />Edit</button>{/if}
        {/if}
      </div>
    {/if}
  </header>

  {#if readOnly}
    <p class="banner"><Symbol name="lock" size={14} />You may read this policy set but not change it — that takes <code>Manage</code> on the policy set.</p>
  {/if}

  {#if phase === "loading"}
    <div class="card"><span class="skeleton" style="width: 50%"></span></div>
  {:else if phase === "unadministered"}
    <div class="card empty">
      <Symbol name="policy" size={28} weight={1.4} />
      <h2>Policy is not administered here</h2>
      <p class="muted">This deployment reads its policy from a file. Policy administration needs authentication enabled; the file is then the first revision.</p>
    </div>
  {:else if phase === "error"}
    <div class="card empty"><Symbol name="warning" size={24} /><p>{loadError}</p></div>
  {:else if current}
    {#if editing}
      <textarea class="editor" bind:value={draft} spellcheck="false" aria-label="Policy text"></textarea>
      <p class="muted hint">⌘S to review. Nothing changes until you save, and the server checks the text and refuses a change that would lock you out.</p>
    {:else}
      <CodeView text={current.source} label="Policy text in force" />
    {/if}
  {/if}
</section>

{#if reviewing && current}
  <Sheet title="Review changes" wide onclose={() => (reviewing = false)}>
    <Diff before={current.source} after={draft} label="Changes to the policy set" />
    <label class="note">
      <span>Note</span>
      <input type="text" bind:value={note} placeholder="Why — it is kept with the revision" />
    </label>
    {#if saveError}<p class="error" role="alert"><Symbol name="warning" size={14} />{saveError}</p>{/if}
    {#snippet actions()}
      <button class="btn" onclick={() => (reviewing = false)}>Keep editing</button>
      <button class="btn primary" disabled={saving} onclick={save}>{saving ? "Saving…" : "Save"}</button>
    {/snippet}
  </Sheet>
{/if}

{#if versionsOpen && current}
  <Sheet title="Versions" wide onclose={() => (versionsOpen = false)}>
    <div class="versions">
      <ol aria-label="Revisions">
        {#each history as r (r.sequence)}
          <li>
            <button class:sel={picked?.sequence === r.sequence} disabled={r.sequence === current.sequence} onclick={() => pick(r.sequence)}>
              <span class="seq num">{r.sequence}</span>
              <span class="who">
                <span>{r.note ?? (r.sequence === current.sequence ? "In force" : "No note")}</span>
                <span class="muted small">by <span title={r.author}>{by(r.author)}</span> · {ago(r.created_at_ms)}</span>
              </span>
              {#if r.sequence === current.sequence}<span class="state allowed tiny">in force</span>{/if}
            </button>
          </li>
        {/each}
      </ol>
      <div class="compare">
        {#if picked}
          <p class="muted">Restoring revision {picked.sequence} would change what is in force:</p>
          <Diff before={current.source} after={picked.source} label={`Restoring revision ${picked.sequence}`} />
        {:else if history.length <= 1}
          <p class="muted">There is only one revision.</p>
        {:else}
          <p class="muted">Pick a revision to see what restoring it would change.</p>
        {/if}
      </div>
    </div>
    {#snippet actions()}
      <button class="btn" onclick={() => (versionsOpen = false)}>Done</button>
      {#if picked && !readOnly}
        <button class="btn primary" onclick={() => restore(picked!.sequence)}><Symbol name="restore" size={14} />Restore revision {picked.sequence}</button>
      {/if}
    {/snippet}
  </Sheet>
{/if}

{#if toast}
  <div class="toast glass" role="status">
    <Symbol name={toast.icon ?? "check"} size={14} />{toast.text}
    {#if toast.undoTo !== undefined && !readOnly}
      <button class="btn plain" onclick={() => restore(toast!.undoTo!, true)}>Undo</button>
    {/if}
  </div>
{/if}

<style>
  .page {
    height: 100%;
    overflow: auto;
    padding: var(--s5) var(--s6) var(--s6);
    display: flex;
    flex-direction: column;
    gap: var(--s3);
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--s4);
  }
  h1 {
    margin: 0;
    font: 700 22px/1.2 var(--display);
  }
  .head p {
    margin: 4px 0 0;
  }
  .actions {
    display: flex;
    gap: 8px;
  }
  .banner {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    padding: 8px 12px;
    border-radius: var(--r);
    background: var(--fill);
    color: var(--text-2);
  }
  .editor {
    flex: 1;
    min-height: 50vh;
    font: 12px/1.6 var(--mono);
    padding: 10px 14px;
    border-radius: var(--r);
    resize: none;
    tab-size: 2;
  }
  .hint {
    margin: 0;
    font-size: 12px;
  }
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 6px;
    padding: var(--s6);
    color: var(--muted);
  }
  .empty h2 {
    margin: 0;
    font: 600 15px/1.3 var(--display);
    color: var(--text);
  }
  .empty p {
    max-width: 46ch;
    margin: 0;
  }
  .note {
    display: grid;
    gap: 4px;
    margin-top: var(--s3);
  }
  .note span {
    font-size: 11px;
    color: var(--muted);
  }
  .error {
    display: flex;
    gap: 6px;
    align-items: center;
    color: var(--denied);
    margin: var(--s3) 0 0;
  }
  .versions {
    display: grid;
    grid-template-columns: 240px minmax(0, 1fr);
    gap: var(--s4);
    min-height: 50vh;
  }
  .versions ol {
    list-style: none;
    margin: 0;
    padding: 0;
    overflow: auto;
    max-height: 60vh;
  }
  .versions li button {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border: none;
    border-radius: var(--r-sm);
    background: none;
    text-align: left;
  }
  .versions li button:hover:not(:disabled) {
    background: var(--fill);
  }
  .versions li button.sel {
    background: var(--accent);
    color: #fff;
  }
  .versions li button.sel .muted {
    color: rgba(255, 255, 255, 0.8);
  }
  .versions li button:disabled {
    cursor: default;
  }
  .seq {
    font-weight: 600;
    width: 2.5ch;
    text-align: right;
  }
  .who {
    flex: 1;
    display: grid;
    min-width: 0;
  }
  .who > span:first-child {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .small {
    font-size: 11px;
  }
  .tiny {
    font-size: 10px;
  }
  .compare p {
    margin: 0 0 8px;
  }
  .toast {
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    z-index: 80;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px 8px 14px;
    border-radius: 999px;
    border: 0.5px solid var(--separator);
    box-shadow: var(--shadow);
  }
</style>
