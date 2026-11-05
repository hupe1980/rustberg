<script lang="ts">
  // What a change does to the text, line by line: added and removed lines carry a sign and a tint, never
  // colour alone.
  import { changes, diff, fold, type DiffLine } from "../lib/diff";
  import { tokenize } from "../lib/cedar";
  let { before, after, label }: { before: string; after: string; label: string } = $props();
  const lines = $derived(diff(before.replace(/\n$/, ""), after.replace(/\n$/, "")));
  const counts = $derived(changes(lines));
  let opened = $state(new Set<number>());
  const rows = $derived(
    fold(lines).flatMap((r, i): (DiffLine | { kind: "fold"; count: number; at: number })[] =>
      r.kind !== "fold" ? [r] : opened.has(i) ? r.lines : [{ kind: "fold", count: r.lines.length, at: i }],
    ),
  );
</script>

<p class="summary">
  {#if counts.added === 0 && counts.removed === 0}
    No changes.
  {:else}
    <span class="add">+{counts.added}</span> <span class="del">−{counts.removed}</span>
    <span class="muted">line{counts.added + counts.removed === 1 ? "" : "s"} changed</span>
  {/if}
</p>
<!-- A scrollable region must be reachable from the keyboard (axe: scrollable-region-focusable). -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div class="diff" role="region" aria-label={label} tabindex="0">
  <table>
    <tbody>
      {#each rows as l, i (i)}
        {#if l.kind === "fold"}
          <tr class="fold">
            <td colspan="4">
              <button onclick={() => (opened = new Set(opened).add(l.at))}>
                ⋯ {l.count} unchanged line{l.count === 1 ? "" : "s"}
              </button>
            </td>
          </tr>
        {:else}
        <tr class={l.kind}>
          <td class="n num" aria-hidden="true">{l.old ?? ""}</td>
          <td class="n num" aria-hidden="true">{l.new ?? ""}</td>
          <td class="sign" aria-label={l.kind === "add" ? "added" : l.kind === "del" ? "removed" : undefined}
            >{l.kind === "add" ? "+" : l.kind === "del" ? "−" : " "}</td
          >
          <td class="l">{#each tokenize(l.text) as t, k (k)}<span class={t.kind}>{t.text}</span>{/each}&#8203;</td>
        </tr>
        {/if}
      {/each}
    </tbody>
  </table>
</div>

<style>
  .summary {
    margin: 0 0 8px;
    font-size: 12px;
  }
  .summary .add {
    color: var(--allowed);
    font-weight: 600;
  }
  .summary .del {
    color: var(--denied);
    font-weight: 600;
  }
  .diff {
    border: 0.5px solid var(--separator);
    border-radius: var(--r);
    overflow: auto;
    background: var(--surface);
    font: 12px/1.6 var(--mono);
    max-height: 56vh;
  }
  table {
    border-collapse: collapse;
    width: 100%;
  }
  td {
    white-space: pre;
    vertical-align: top;
    padding: 0 10px 0 0;
  }
  .n {
    width: 1%;
    padding: 0 8px;
    text-align: right;
    color: var(--faint);
    user-select: none;
  }
  .sign {
    width: 1%;
    padding: 0 6px;
    user-select: none;
    font-weight: 600;
  }
  tr.fold td {
    padding: 0;
    background: var(--fill);
  }
  tr.fold button {
    all: unset;
    display: block;
    width: 100%;
    box-sizing: border-box;
    padding: 2px 12px;
    color: var(--muted);
    font: 11px/1.8 var(--font);
    cursor: pointer;
  }
  tr.fold button:hover {
    color: var(--accent);
  }
  tr.fold button:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }
  tr.add {
    background: var(--diff-add);
  }
  tr.add .sign {
    color: var(--allowed);
  }
  tr.del {
    background: var(--diff-del);
  }
  tr.del .sign {
    color: var(--denied);
  }
  .kw {
    color: var(--code-keyword);
    font-weight: 600;
  }
  .ann {
    color: var(--code-annotation);
    font-weight: 600;
  }
  .str {
    color: var(--code-string);
  }
  .com {
    color: var(--code-comment);
    font-style: italic;
  }
</style>
