+++
title = "Documentation"
description = "How Rustberg authenticates callers, authorizes every operation against Cedar policy, federates catalogs, vends storage credentials, and records what it decided."
sort_by = "weight"
template = "docs-section.html"
page_template = "docs-page.html"
+++

Rustberg is one authenticated, policy-controlled Apache Iceberg REST endpoint in
front of every catalog you own — a single Rust binary, and an embeddable crate.

- **Try it:** [Getting started](@/docs/getting-started.md). One command brings up
  a catalog, mints an admin key and prints the `curl` that uses it.
- **Evaluate it:** [Architecture](@/docs/architecture.md) for how a request is
  decided, then [Security](@/docs/security.md) for what is enforced and where
  enforcement stops.
