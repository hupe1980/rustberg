<script lang="ts">
  // One sheet, four clients, this server's address filled in. The credential is masked until revealed,
  // and copying takes it either way.
  import Sheet from "./Sheet.svelte";
  import Symbol from "./Symbol.svelte";
  import { masked, snippets } from "../lib/snippets";
  import { copy } from "../lib/clipboard";
  import { credential } from "../lib/session";
  import { get } from "../lib/api";

  let { onclose }: { onclose: () => void } = $props();
  let chosen = $state(snippets[0]!.id);
  let reveal = $state(false);
  let copied = $state(false);

  const uri = location.origin;
  const token = credential() ?? "rb_...";
  // The warehouse this server serves, which DuckDB attaches by; a placeholder until it is known.
  let warehouse = $state("<warehouse>");
  $effect(() => {
    get<{ overrides?: { warehouse?: string } }>("/v1/config")
      .then((c) => (warehouse = c.overrides?.warehouse ?? warehouse))
      .catch(() => {});
  });
  const snippet = $derived(snippets.find((s) => s.id === chosen)!);
  const shown = $derived(snippet.code(uri, reveal ? token : masked(token), warehouse));

  async function take() {
    copied = await copy(snippet.code(uri, token, warehouse));
    setTimeout(() => (copied = false), 1600);
  }
</script>

<Sheet title="Connect a client" wide {onclose}>
  <div class="tabs" role="tablist" aria-label="Client">
    {#each snippets as s (s.id)}
      <button role="tab" aria-selected={chosen === s.id} class:on={chosen === s.id} onclick={() => (chosen = s.id)}>{s.title}</button>
    {/each}
  </div>
  <div role="tabpanel" aria-label={`${snippet.title} snippet`}><pre class="code"><code>{shown}</code></pre></div>
  <p class="muted small">
    Copy takes the full credential, even while it is hidden. On a restricted table this server plans the read; a
    client that cannot plan remotely gets no storage access — never unfiltered files.
  </p>
  {#snippet actions()}
    <label class="reveal"><input type="checkbox" role="switch" bind:checked={reveal} />Show credential</label>
    <span class="spacer"></span>
    <button class="btn" onclick={onclose}>Done</button>
    <button class="btn primary" onclick={take}><Symbol name={copied ? "check" : "copy"} size={14} />{copied ? "Copied" : "Copy"}</button>
  {/snippet}
</Sheet>

<style>
  .tabs {
    display: inline-flex;
    padding: 2px;
    border-radius: var(--r);
    background: var(--fill);
    margin-bottom: var(--s3);
  }
  .tabs button {
    border: none;
    background: none;
    padding: 4px 14px;
    border-radius: 8px;
  }
  .tabs button.on {
    background: var(--surface);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.12);
    font-weight: 500;
  }
  .code {
    margin: 0;
    padding: 14px 16px;
    border-radius: var(--r);
    background: var(--surface);
    border: 0.5px solid var(--separator);
    font: 12px/1.6 var(--mono);
    overflow: auto;
    user-select: all;
  }
  .small {
    font-size: 12px;
  }
  .reveal {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .spacer {
    flex: 1;
  }
  input[type="checkbox"][role="switch"] {
    appearance: none;
    -webkit-appearance: none;
    flex: none;
    width: 38px;
    height: 22px;
    margin: 0;
    border-radius: 11px;
    background: var(--fill-2);
    position: relative;
    transition: background 160ms var(--ease);
  }
  input[type="checkbox"][role="switch"]::after {
    content: "";
    position: absolute;
    top: 2px;
    left: 2px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
    transition: transform 160ms var(--ease);
  }
  input[type="checkbox"][role="switch"]:checked {
    background: var(--accent);
  }
  input[type="checkbox"][role="switch"]:checked::after {
    transform: translateX(16px);
  }
</style>
