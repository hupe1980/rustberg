<script lang="ts">
  // A read-only document: line numbers, monospace, and — for Cedar — quiet emphasis. Rendered as text
  // nodes only, so whatever a policy contains stays text.
  import { tokenize } from "../lib/cedar";
  let { text, cedar = true, label }: { text: string; cedar?: boolean; label: string } = $props();
  const lines = $derived(text.replace(/\n$/, "").split("\n"));
</script>

<!-- A scrollable region must be reachable from the keyboard (axe: scrollable-region-focusable). -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div class="code" role="region" aria-label={label} tabindex="0">
  <table>
    <tbody>
      {#each lines as line, i (i)}
        <tr>
          <td class="n num" aria-hidden="true">{i + 1}</td>
          <td class="l">{#if cedar}{#each tokenize(line) as t, k (k)}<span class={t.kind}>{t.text}</span>{/each}{:else}{line}{/if}&#8203;</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .code {
    background: var(--surface);
    border: 0.5px solid var(--separator);
    border-radius: var(--r);
    overflow: auto;
    font: 12px/1.6 var(--mono);
  }
  table {
    border-collapse: collapse;
    width: 100%;
  }
  td {
    padding: 0 12px 0 0;
    vertical-align: top;
    white-space: pre;
  }
  .n {
    width: 1%;
    padding: 0 10px 0 14px;
    text-align: right;
    color: var(--faint);
    user-select: none;
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
  tr:first-child td {
    padding-top: 10px;
  }
  tr:last-child td {
    padding-bottom: 10px;
  }
</style>
