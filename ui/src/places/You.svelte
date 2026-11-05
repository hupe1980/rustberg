<script lang="ts">
  // Who the server believes you are — the identity every other screen is filtered by — and how to point
  // a client at this catalog with the same credential.
  import Symbol from "../components/Symbol.svelte";
  import type { Identity } from "../lib/api";

  let {
    identity,
    dev,
    onconnect,
    onsignout,
  }: { identity: Identity | null; dev: boolean; onconnect: () => void; onsignout: () => void } = $props();
  const p = $derived(identity?.principal);
  const initial = $derived((p?.name || p?.id || "?").slice(0, 1).toUpperCase());
  // How a rule names this identity — the one spelling an operator needs from this page.
  const inPolicy = $derived(
    p ? `Rustberg::${p.principal_type === "api_key" ? "ApiKey" : "User"}::${JSON.stringify(p.id)}` : "",
  );
</script>

<section class="page" aria-labelledby="you-title">
  <div class="card who">
    <div class="avatar" aria-hidden="true">{initial}</div>
    <div class="id">
      <h1 id="you-title">{dev ? "Development mode" : (p?.name ?? "—")}</h1>
      {#if dev}
        <p class="muted">Authentication is disabled on this server, so every request is anonymous and every policy that names a principal is skipped. Never run this way with data that matters.</p>
      {:else if p}
        <p class="muted"><span class="small">In a policy</span> <code class="mono" title="How a rule names you">{inPolicy}</code></p>
      {/if}
    </div>
  </div>

  {#if p && !dev}
    <div class="card">
      <h2 class="section-title">Identity</h2>
      <dl>
        <dt>Tenant</dt><dd class="mono">{p.tenant_id}</dd>
        <dt>Roles</dt>
        <dd>
          {#each p.roles as r (r)}<span class="role">{r}</span>{:else}<span class="muted">none</span>{/each}
        </dd>
        <dt>Signed in with</dt><dd>{p.auth_method === "api_key" ? "API key" : p.auth_method === "jwt" ? "Token (OIDC)" : p.auth_method}</dd>
        {#if p.expires_at}<dt>Expires</dt><dd>{new Date(p.expires_at).toLocaleString()}</dd>{/if}
      </dl>
      <p class="muted small">
        Policies match on these roles. What you see anywhere in this console is what this identity is permitted to
        see — another principal may see more, or less.
      </p>
    </div>
  {/if}

  <div class="card connect">
    <div>
      <h2 class="section-title">Connect a client</h2>
      <p class="muted">PyIceberg, Spark, Trino or DuckDB, pointed at this server with your credential.</p>
    </div>
    <button class="btn primary" onclick={onconnect}><Symbol name="plug" size={14} />Connect a client…</button>
  </div>

  {#if !dev}
    <div class="signout">
      <button class="btn plain" onclick={onsignout}><Symbol name="signout" size={14} />Sign out</button>
      <p class="muted small">Forgets the credential in this tab. Nothing is stored anywhere else.</p>
    </div>
  {/if}
</section>

<style>
  .page {
    height: 100%;
    overflow: auto;
    padding: var(--s5) var(--s6) var(--s6);
    display: grid;
    gap: var(--s4);
    align-content: start;
    max-width: 760px;
  }
  .who {
    display: flex;
    gap: var(--s4);
    align-items: center;
  }
  .avatar {
    width: 56px;
    height: 56px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    font: 600 24px/1 var(--display);
    color: #fff;
    background: linear-gradient(180deg, #5e9cff, var(--accent));
    flex: none;
  }
  h1 {
    margin: 0;
    font: 700 22px/1.2 var(--display);
  }
  .id p {
    margin: 4px 0 0;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 8px 20px;
    margin: 0 0 var(--s3);
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
  }
  .role {
    display: inline-block;
    padding: 1px 8px;
    margin: 0 4px 2px 0;
    border-radius: 999px;
    background: var(--accent-soft);
    color: var(--accent-ink);
    font-weight: 500;
  }
  .small {
    font-size: 12px;
    margin: 0;
  }
  .connect {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--s4);
  }
  .connect p {
    margin: 0;
  }
  .signout {
    display: flex;
    align-items: center;
    gap: var(--s3);
  }
</style>
