<script lang="ts">
  // A sheet: modal, one at a time, glass, Esc to close. Focus moves in on open and back on close.
  import type { Snippet } from "svelte";
  import { tick } from "svelte";
  let {
    title,
    onclose,
    wide = false,
    children,
    actions,
  }: { title: string; onclose: () => void; wide?: boolean; children: Snippet; actions?: Snippet } = $props();

  let panel: HTMLElement | undefined = $state();
  const previous = document.activeElement as HTMLElement | null;

  $effect(() => {
    void tick().then(() => {
      const first = panel?.querySelector<HTMLElement>("input, textarea, button, [tabindex='0']");
      (first ?? panel)?.focus();
    });
    return () => previous?.focus?.();
  });

  function key(e: KeyboardEvent) {
    if (e.key === "Escape") {
      e.stopPropagation();
      onclose();
    }
  }
</script>

<div class="scrim" role="presentation" onclick={onclose}></div>
<div
  class="sheet glass"
  class:wide
  role="dialog"
  aria-modal="true"
  aria-labelledby="sheet-title"
  tabindex="-1"
  bind:this={panel}
  onkeydown={key}
>
  <h2 id="sheet-title">{title}</h2>
  <div class="body">{@render children()}</div>
  {#if actions}<footer>{@render actions()}</footer>{/if}
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 60;
    background: rgba(0, 0, 0, 0.18);
  }
  .sheet {
    position: fixed;
    z-index: 61;
    left: 50%;
    top: 8vh;
    transform: translateX(-50%);
    width: min(560px, calc(100vw - 32px));
    max-height: 84vh;
    display: flex;
    flex-direction: column;
    border-radius: var(--r-xl);
    border: 0.5px solid var(--separator);
    box-shadow: var(--shadow-sheet);
    outline: none;
    animation: rise 180ms var(--ease);
  }
  .sheet.wide {
    width: min(1040px, calc(100vw - 32px));
  }
  h2 {
    margin: 0;
    padding: 18px 22px 6px;
    font: 600 15px/1.3 var(--display);
  }
  .body {
    padding: 8px 22px 16px;
    overflow: auto;
  }
  footer {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 8px;
    padding: 12px 22px 18px;
  }
  @keyframes rise {
    from {
      opacity: 0;
      transform: translate(-50%, 8px);
    }
  }
</style>
