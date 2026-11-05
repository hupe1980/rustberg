// Small formatting helpers, one place for each.
export const ident = (ns: string[], name?: string) => [...ns, ...(name ? [name] : [])].join(".");

export function when(ms: number): string {
  const d = new Date(ms);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function ago(ms: number, now = Date.now()): string {
  const s = Math.round((now - ms) / 1000);
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

/** An Iceberg type, as one line. */
export function typeName(t: unknown): string {
  if (typeof t === "string") return t;
  const o = t as { type?: string; element?: unknown; key?: unknown; value?: unknown };
  if (o?.type === "list") return `list<${typeName(o.element)}>`;
  if (o?.type === "map") return `map<${typeName(o.key)}, ${typeName(o.value)}>`;
  if (o?.type === "struct") return "struct";
  return String(o?.type ?? "?");
}
