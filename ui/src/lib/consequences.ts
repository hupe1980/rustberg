// A review's consequences as sentences a person reads: who, gains or loses, what, on which table, and how
// strongly a gained read holds. Words only — the server decided every row.
import type { Impact, ImpactChange, ImpactSubject } from "./api";

export function who(s: ImpactSubject): string {
  if (s.kind === "group") return `Members of ${s.roles[0]}`;
  if (s.kind === "anyone") return "Anyone in no group";
  if (s.kind === "api_key") return `API key ${s.id}`;
  return s.id;
}

const strength: Record<string, string> = {
  none: "unrestricted",
  architectural: "restricted — holds against any engine",
  cooperative: "restricted — holds only in an engine that applies it",
};

/** One sentence per change, without the subject (the group heading says who). */
export function sentence(c: ImpactChange): string {
  const target = c.resource === "policy set" ? "the policy set" : c.resource;
  if (c.change === "restriction") {
    const was = c.before ? strength[c.before.grade] : "";
    const now = c.after ? strength[c.after.grade] : "";
    return `${c.action} on ${target} changes: ${was} → ${now}`;
  }
  const how = c.change === "gains" && c.after ? ` (${strength[c.after.grade]})` : "";
  return `${c.change} ${c.action} on ${target}${how}`;
}

/** Rows grouped by principal, in the server's order. */
export function grouped(impact: Impact): { subject: ImpactSubject; changes: ImpactChange[] }[] {
  const out: { subject: ImpactSubject; changes: ImpactChange[] }[] = [];
  for (const c of impact.changes) {
    const last = out[out.length - 1];
    if (last && last.subject.kind === c.principal.kind && last.subject.id === c.principal.id) last.changes.push(c);
    else out.push({ subject: c.principal, changes: [c] });
  }
  return out;
}

/** What the answer covered, said plainly — and that it is not a proof. */
export function coverage(impact: Impact): string {
  const p = impact.checked.principals.length;
  const t = impact.checked.tables;
  const base = `Checked ${p} ${p === 1 ? "principal" : "principals"} the rules name across ${t} ${t === 1 ? "table" : "tables"} you may read`;
  return impact.checked.truncated
    ? `${base} — partial: ${impact.checked["unchecked-tables"]} more tables were not checked.`
    : `${base}. Exact for those; not a proof for anyone else.`;
}
