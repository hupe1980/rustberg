// An Iceberg JSON predicate, as a person reads it: `region = 'EU' and amount > 10`. Presentation only —
// the server decides what a filter means; this only names the columns its field ids point at.
type Expr = Record<string, unknown>;

const OPS: Record<string, string> = {
  eq: "=", "not-eq": "≠", lt: "<", "lt-eq": "≤", gt: ">", "gt-eq": "≥",
  "starts-with": "starts with", "not-starts-with": "does not start with",
};

export function describe(expr: unknown, names: Map<number, string>): string {
  if (expr === true || (expr as Expr)?.type === "true") return "every row";
  if (expr === false || (expr as Expr)?.type === "false") return "no rows";
  const e = expr as Expr;
  if (!e || typeof e !== "object") return JSON.stringify(expr);
  const type = String(e.type);
  const term = () => name(e.term ?? e.left ?? e.child, names);
  const value = () => literal(e.value ?? e.right);
  switch (type) {
    case "and":
    case "or":
      return `${group(e.left, names, type)} ${type} ${group(e.right, names, type)}`;
    case "not":
      return `not (${describe(e.child, names)})`;
    case "is-null":
      return `${term()} is null`;
    case "not-null":
      return `${term()} is not null`;
    case "is-nan":
      return `${term()} is NaN`;
    case "not-nan":
      return `${term()} is not NaN`;
    case "in":
    case "not-in": {
      const values = ((e.values as unknown[]) ?? []).map(literal).join(", ");
      return `${term()} ${type === "in" ? "in" : "not in"} (${values})`;
    }
    default:
      return OPS[type] ? `${term()} ${OPS[type]} ${value()}` : JSON.stringify(expr);
  }
}

function group(child: unknown, names: Map<number, string>, parent: string): string {
  const text = describe(child, names);
  const t = (child as Expr)?.type;
  return (t === "and" || t === "or") && t !== parent ? `(${text})` : text;
}

function name(term: unknown, names: Map<number, string>): string {
  if (typeof term === "string") return term;
  const t = term as Expr;
  if (typeof t?.id === "number") return names.get(t.id) ?? `#${t.id}`;
  if (typeof t?.name === "string") return t.name;
  if (t?.term) return name(t.term, names);
  return JSON.stringify(term);
}

function literal(v: unknown): string {
  const inner = (v as Expr)?.type === "literal" ? (v as Expr).value : v;
  return typeof inner === "string" ? `'${inner}'` : JSON.stringify(inner);
}
