<script lang="ts">
  // What a policy text would change, for whom — before the diff of what was typed. The server's two
  // authorizers decide every row; this renders sentences and says what was checked.
  import Symbol from "./Symbol.svelte";
  import { ApiError, impact, type Impact } from "../lib/api";
  import { coverage, grouped, sentence, who } from "../lib/consequences";

  let { source, label }: { source: string; label: string } = $props();

  let answer = $state<Impact | null>(null);
  let failure = $state<ApiError | null>(null);

  $effect(() => {
    const text = source;
    answer = null;
    failure = null;
    impact(text)
      .then((a) => (answer = a))
      .catch((e) => (failure = e));
  });

  const groups = $derived(answer ? grouped(answer) : []);
</script>

<section class="consequences" aria-label={label} aria-busy={!answer && !failure}>
  <h3 class="section-title">Who gains, who loses</h3>
  {#if failure}
    <p class="muted small">
      <Symbol name="info" size={12} />
      {failure.status === 400 ? "Consequences appear once the text is valid." : "Consequences could not be computed: " + failure.message}
    </p>
  {:else if !answer}
    <span class="skeleton" style="width: 55%"></span>
  {:else if !groups.length}
    <p class="none"><Symbol name="check" size={14} />No one gains or loses access.</p>
  {:else}
    <ul>
      {#each groups as g (g.subject.kind + g.subject.id)}
        <li>
          <strong>{who(g.subject)}</strong>
          <ul>
            {#each g.changes as c (c.resource + c.action)}
              <li class={c.change}>
                <Symbol name={c.change === "gains" ? "plus" : c.change === "loses" ? "xmark" : "shield"} size={12} />
                <span><span class="verb">{c.change === "restriction" ? "" : c.change}</span>{sentence(c).replace(/^(gains|loses) /, " ")}</span>
              </li>
            {/each}
          </ul>
        </li>
      {/each}
    </ul>
  {/if}
  {#if answer}
    <p class="coverage muted small" class:partial={answer.checked.truncated}>
      {#if answer.checked.truncated}<Symbol name="warning" size={12} />{/if}{coverage(answer)}
    </p>
  {/if}
</section>

<style>
  .consequences {
    display: grid;
    gap: var(--s2);
    margin-bottom: var(--s3);
  }
  h3 {
    margin: 0;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: var(--s2);
  }
  ul ul {
    margin-top: 4px;
    gap: 2px;
  }
  li li {
    display: flex;
    gap: 6px;
    align-items: baseline;
  }
  .verb {
    font-weight: 600;
  }
  .gains .verb,
  .gains :global(svg) {
    color: var(--allowed);
  }
  .loses .verb,
  .loses :global(svg) {
    color: var(--denied);
  }
  .restriction :global(svg) {
    color: var(--restricted);
  }
  .none {
    display: flex;
    gap: 6px;
    align-items: center;
    margin: 0;
    color: var(--allowed);
  }
  .coverage {
    margin: 0;
    display: flex;
    gap: 6px;
    align-items: center;
  }
  .coverage.partial {
    color: var(--restricted);
  }
  p {
    margin: 0;
  }
</style>
