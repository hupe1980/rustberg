<script lang="ts">
  // ⌘K: every place, object and action by name, like Spotlight for the window — the one search location.
  import { tick } from "svelte";
  import Symbol from "./Symbol.svelte";

  export type Command = { id: string; title: string; hint?: string; terms?: string; icon: string; run: () => void };
  let { commands, onclose }: { commands: Command[]; onclose: () => void } = $props();

  let q = $state("");
  let index = $state(0);
  let input: HTMLInputElement | undefined = $state();
  // Like Spotlight: a name that starts with what you typed first, then a word that does, then anything
  // containing it; otherwise the order given.
  const rank = (c: Command, n: string) => {
    const title = c.title.toLowerCase();
    const all = `${title} ${c.hint ?? ""} ${c.terms ?? ""}`.toLowerCase();
    return title.startsWith(n) ? 0 : all.split(/[\s.]+/).some((w) => w.startsWith(n)) ? 1 : all.includes(n) ? 2 : 3;
  };
  const shown = $derived.by(() => {
    const n = q.trim().toLowerCase();
    if (!n) return commands.slice(0, 12);
    return commands
      .map((c) => [c, rank(c, n)] as const)
      .filter(([, r]) => r < 3)
      .sort((a, b) => a[1] - b[1])
      .map(([c]) => c)
      .slice(0, 12);
  });
  const active = $derived(shown[index]);

  $effect(() => {
    void tick().then(() => input?.focus());
  });

  function run(c: Command) {
    onclose();
    c.run();
  }

  function key(e: KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      index = Math.min(shown.length - 1, index + 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      index = Math.max(0, index - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const c = shown[index];
      if (c) run(c);
    } else if (e.key === "Escape") {
      onclose();
    }
  }
</script>

<div class="scrim" role="presentation" onclick={onclose}></div>
<div class="palette glass" role="dialog" aria-modal="true" aria-label="Go to">
  <div class="field">
    <Symbol name="search" size={16} />
    <input
      bind:this={input}
      bind:value={q}
      oninput={() => (index = 0)}
      onkeydown={key}
      placeholder="Go to a table, view, namespace or action"
      aria-label="Go to"
      role="combobox"
      aria-expanded="true"
      aria-controls="palette-list"
      aria-activedescendant={active ? `cmd-${active.id}` : undefined}
    />
  </div>
  <!-- Focus stays in the field (aria-activedescendant), so an option takes the pointer but never focus,
       and the arrow keys and Enter above are its keyboard path. -->
  <ul id="palette-list" role="listbox" aria-label="Results">
    {#each shown as c, i (c.id)}
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <li id={`cmd-${c.id}`} role="option" aria-selected={i === index} class:sel={i === index} onmouseenter={() => (index = i)} onclick={() => run(c)}>
        <Symbol name={c.icon} size={15} /><span class="t">{c.title}</span>{#if c.hint}<span class="h">{c.hint}</span>{/if}
      </li>
    {/each}
  </ul>
  {#if !shown.length}<p class="none" role="status">No matches</p>{/if}
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 70;
    background: rgba(0, 0, 0, 0.08);
  }
  .palette {
    position: fixed;
    z-index: 71;
    left: 50%;
    top: 16%;
    transform: translateX(-50%);
    width: min(580px, calc(100vw - 32px));
    border-radius: var(--r-xl);
    border: 0.5px solid var(--separator);
    box-shadow: var(--shadow-sheet);
    overflow: hidden;
  }
  .field {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 18px;
    color: var(--muted);
    border-bottom: 0.5px solid var(--separator);
  }
  .field input {
    flex: 1;
    border: none;
    background: none;
    font-size: 17px;
    outline: none;
    padding: 0;
    color: var(--text);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 6px;
    max-height: 380px;
    overflow-y: auto;
  }
  li {
    display: flex;
    cursor: default;
    align-items: center;
    gap: 10px;
    padding: 7px 10px;
    border-radius: 8px;
  }
  li.sel {
    background: var(--accent);
    color: #fff;
  }
  .t {
    flex: 1;
  }
  .h {
    font-size: 11px;
    opacity: 0.75;
    font-family: var(--mono);
  }
  .none {
    padding: 10px;
    color: var(--muted);
  }
</style>
