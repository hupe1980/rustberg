+++
title = "Console"
description = "The built-in web console: browse the catalog as yourself, see what is restricted for you and how strongly it holds, preview anyone else's view, and edit, review and restore the policy set."
weight = 13
+++

The web console is built into the binary. Open **`/ui/`** on your server
(`http://localhost:8000/ui/` by default): no install, extra port or second
process.

Every screen is drawn with your own credential, so it shows exactly what a
client using that credential receives. An administrator and an analyst see
different answers for the same table.

{{ <shot name="table-restricted" alt="The orders table seen by an analyst: Restricted, rows where region is EU, the email column masked, planning server-side." caption="bob, an analyst, opens sales.orders: restricted to region = 'EU', email masked." /> }}

## Sign in

Paste an API key or a JWT. It is kept in this browser tab only
(`sessionStorage`), never in a cookie or on disk, and is gone when the tab
closes or on **Sign out** (**You** page). With `--dev --no-auth` you are signed
in automatically.

## Three places

**Catalog** (⌘1): namespaces, tables and views in a sidebar. A table opens on
**What you can see**:

- **Unrestricted**: no row filter or column mask applies to you.
- **Restricted**: your row filter in plain words (`region = 'EU'`) and your
  masked columns. The server withholds storage credentials and plans your reads,
  handing over only the files the filter selects.
- **Strength**: the [enforcement grade](@/docs/authorization.md#how-strongly-it-holds-the-enforcement-grade)
  in words — *Holds against any engine*, or *Holds only in an engine that applies
  it* and why (a filter column that does not separate files, a masked column the
  file still holds).

**View as** (the eye in the toolbar, or ⌘K → *View as…*): an administrator names
a principal and roles, and *What you can see* becomes *What bob would see* —
answered by the server's [what-if](@/docs/authorization.md#ask-before-you-ship-what-would-they-get)
with your own credential, including the policies that decided and the concrete
change that would make the restriction hold against any engine. Nothing is read
as Bob; the toolbar says *Previewing as bob* until you end it. It needs `Read`
on the policy set.

**Who can read this** (inspector, for anybody who may read the policy set): every
principal the rules name, with *everything*, *filtered rows*, *masked columns* or
*nothing*, and a one-click **View as** on each.

{{ <shot name="view-as" alt="alice previews the orders table as bob: what bob would see, how strongly it holds, the remedy and the policy that granted it." caption="View as: what bob would see, answered by the server's what-if — nothing is read as bob." /> }}

A refusal shows its **Reference** — the server's request id. Copy it to an
administrator: it is the `request_id` of the decision in the audit trail.

{{ <shot name="table-unrestricted" alt="The same orders table seen by an administrator: Unrestricted." caption="alice, an administrator, opens the same table: unrestricted." /> }}

Below: schema (masked columns marked), partition specs, snapshots and
properties. The inspector (⌘I) shows location, UUID and format version.

**Policies** (⌘2): the Cedar policy set in force.

- **Edit** → **Review** leads with **who gains, who loses** — *Members of
  marketing gains Read on sales.orders (restricted — holds only in an engine that
  applies it)* — computed by the server for the people your rules name, then the
  line diff and a note; **Save** installs a new revision. The server validates the text and refuses a change that would
  lock you out of changing policy; the draft is kept.
- **Versions** lists revisions and shows what restoring one would change — the
  same consequences first, then the diff.
  **Restore** asks no question: it creates a new revision, and **Undo** in the
  confirmation brings the previous rules back.
- Reading policy takes `Read` on the policy set; changing it takes `Manage`.
  Without `Manage` the console turns read-only after the first refused attempt.

{{ <shot name="review" alt="The Review changes sheet: a one-line diff of the policy set and a note, before Save." caption="Review: the diff and a note, before anything is installed." /> }}

{{ <shot name="versions" alt="The Versions sheet: revision 1 selected, with the lines restoring it would remove." caption="Versions: what restoring revision 1 would change." /> }}

**You** (⌘3): your principal, tenant and roles, and **Connect a client**:
copyable PyIceberg, Spark, Trino and DuckDB configuration with this server's
address filled in. The credential is hidden until shown; **Copy** takes the full
value. See [Clients and engines](@/docs/clients.md).

{{ <shot name="connect" alt="The Connect a client sheet with a PyIceberg snippet; the credential is hidden." caption="Connect a client: this server's address filled in, the credential hidden until you show it." /> }}

**⌘K** searches tables, views, places and actions by name.

{{ <shot name="palette" alt="The Go to palette with ord typed and the orders table as the first result." caption="⌘K: the whole catalog by name." /> }}

## Security

- Static files compiled into the binary, served under `/ui/` with their own
  Content Security Policy: script only from the server (never inline), no
  request to other origins, no framing.
- Calls the same REST and management API as every client, with your bearer
  token. No privileged endpoint, no session of its own. It computes no policy or
  enforcement answer itself — it renders what the server sent.
- The API keeps its stricter policy (`default-src 'none'`).

## Switch it off

```toml
[server.ui]
enabled = false
```

The `/ui` routes are then not mounted. To leave the console out of the binary,
build without the `ui` feature:

```bash
cargo build --release --no-default-features --features cli,tls,storage-all
```

## Building from source

Release binaries, the container image and the crates.io package contain the
console. A git checkout embeds whatever is in `ui/dist`; build it once with
Node 24:

```bash
just ui        # npm ci && npm run build in ui/
cargo build --release
```

Without it the build succeeds with a warning, and `/ui/` serves a page saying
how to build the console.

- `just ui-dev`: live reload against a server on port 8000.
- `just shots`: retakes this page's screenshots from a real server, both themes
  (needs a local Chrome).
