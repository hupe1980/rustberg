<script lang="ts">
  // Preview the catalog as another principal. The server's what-if answers, with your own credential;
  // nothing is fetched as them, and the toolbar says it is a preview for as long as it lasts.
  import Sheet from "./Sheet.svelte";
  import Symbol from "./Symbol.svelte";
  import { untrack } from "svelte";
  import type { Subject } from "../lib/api";

  let { current, onclose, onpreview }: { current: Subject | null; onclose: () => void; onpreview: (s: Subject) => void } =
    $props();

  // The form starts from the preview in force, then belongs to the person typing.
  const initial = untrack(() => current);
  let id = $state(initial?.id ?? "");
  let kind = $state<Subject["kind"]>(initial?.kind ?? "user");
  let roles = $state(initial?.roles.join(", ") ?? "");

  function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!id.trim()) return;
    onpreview({
      id: id.trim(),
      kind,
      roles: roles
        .split(",")
        .map((r) => r.trim())
        .filter(Boolean),
    });
  }
</script>

<Sheet title="View as…" {onclose}>
  <form id="view-as" class="form" onsubmit={submit}>
    <label>
      <span>Principal</span>
      <input bind:value={id} placeholder="bob, or an API key's name" autocomplete="off" spellcheck="false" required />
    </label>
    <fieldset class="kind">
      <legend>Kind</legend>
      <label class:on={kind === "user"}><input type="radio" bind:group={kind} value="user" />Person (token)</label>
      <label class:on={kind === "api_key"}><input type="radio" bind:group={kind} value="api_key" />API key</label>
    </fieldset>
    <label>
      <span>Roles</span>
      <input bind:value={roles} placeholder="analyst, eu" autocomplete="off" spellcheck="false" />
    </label>
    <p class="muted small">
      <Symbol name="info" size={12} />
      Answered by the server with your own credential, in your tenant — nothing is read as them. Needs permission to read
      the policy set.
    </p>
  </form>
  {#snippet actions()}
    <button class="btn" type="button" onclick={onclose}>Cancel</button>
    <button class="btn primary" type="submit" form="view-as" disabled={!id.trim()}><Symbol name="eye" size={14} />Preview</button>
  {/snippet}
</Sheet>

<style>
  .form {
    display: grid;
    gap: var(--s3);
  }
  label {
    display: grid;
    gap: 4px;
  }
  label > span,
  legend {
    color: var(--muted);
    font-size: 12px;
  }
  input:not([type="radio"]) {
    font: inherit;
    padding: 8px 10px;
    border-radius: var(--r-sm);
    border: 1px solid var(--separator);
    background: var(--surface, transparent);
    color: inherit;
  }
  input:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }
  .kind {
    border: 0;
    padding: 0;
    margin: 0;
    display: flex;
    gap: var(--s2);
    flex-wrap: wrap;
  }
  .kind legend {
    margin-bottom: 4px;
  }
  .kind label {
    display: inline-flex;
    gap: 6px;
    align-items: center;
    padding: 6px 10px;
    border-radius: var(--r-sm);
    border: 1px solid var(--separator);
    cursor: pointer;
  }
  .kind label.on {
    border-color: var(--accent);
    background: var(--accent-soft);
  }
  p {
    display: flex;
    gap: 6px;
    align-items: flex-start;
    margin: 0;
  }
</style>
