// One way to call the server: the credential as a bearer header (an API key is a bearer token), the
// server's own error envelope surfaced as it is, and a rejected credential forgotten.
import { credential, forget } from "./session";
import { parseGrade, type Grade } from "./grade";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public kind?: string,
    /** The server's request id: the one string that finds this refusal in the audit trail. */
    public reference?: string,
  ) {
    super(message);
  }
}

let onUnauthorized: () => void = () => {};
export function whenUnauthorized(handler: () => void): void {
  onUnauthorized = handler;
}

export async function call<T>(method: string, path: string, body?: unknown): Promise<{ data: T; headers: Headers }> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = credential();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
  });

  if (!response.ok) {
    let message = response.statusText || `HTTP ${response.status}`;
    let kind: string | undefined;
    try {
      const envelope = await response.json();
      message = envelope?.error?.message ?? message;
      kind = envelope?.error?.type;
    } catch {
      /* not JSON */
    }
    if (response.status === 401) {
      forget();
      onUnauthorized();
    }
    throw new ApiError(response.status, message, kind, response.headers.get("x-request-id") ?? undefined);
  }
  const text = await response.text();
  return { data: (text ? JSON.parse(text) : undefined) as T, headers: response.headers };
}

export const get = async <T>(path: string) => (await call<T>("GET", path)).data;

// ── Paths ──────────────────────────────────────────────────────────────────

/** A namespace on the wire: its parts joined by the unit separator, then percent-encoded. */
export const nsPath = (ns: string[]) => encodeURIComponent(ns.join("\u001f"));

// ── Shapes this console reads ──────────────────────────────────────────────

export type Identity = {
  principal: {
    id: string;
    name: string;
    principal_type: string;
    tenant_id: string;
    roles: string[];
    auth_method: string;
    expires_at?: string;
  };
};

export type Ident = { namespace: string[]; name: string };

export type Field = { id: number; name: string; required: boolean; type: unknown; doc?: string };
export type Schema = { "schema-id": number; fields: Field[] };
export type PartitionSpec = {
  "spec-id": number;
  fields: { "source-id": number; "field-id": number; name: string; transform: string }[];
};
export type Snapshot = {
  "snapshot-id": number;
  "parent-snapshot-id"?: number;
  "timestamp-ms": number;
  summary?: Record<string, string>;
};
export type TableMetadata = {
  "format-version": number;
  "table-uuid": string;
  location: string;
  schemas: Schema[];
  "current-schema-id": number;
  "partition-specs": PartitionSpec[];
  "default-spec-id": number;
  snapshots?: Snapshot[];
  "current-snapshot-id"?: number;
  properties?: Record<string, string>;
};
export type ReadRestrictions = {
  "required-column-projections"?: { action: string; "field-id": number }[];
  "required-row-filter"?: unknown;
};
export type LoadTable = {
  "metadata-location"?: string;
  metadata: TableMetadata;
  config?: Record<string, string>;
  "read-restrictions"?: ReadRestrictions;
};
export type ViewVersion = {
  "version-id": number;
  "timestamp-ms": number;
  "schema-id": number;
  representations: { type: string; sql?: string; dialect?: string }[];
};
export type LoadView = {
  "metadata-location"?: string;
  metadata: {
    "view-uuid": string;
    location: string;
    schemas: Schema[];
    "current-version-id": number;
    versions: ViewVersion[];
    properties?: Record<string, string>;
  };
};

export type PolicyRevision = {
  sequence: number;
  version: string;
  source: string;
  author: string;
  created_at_ms: number;
  note?: string;
  latest_sequence: number;
};
export type RevisionSummary = {
  sequence: number;
  version: string;
  author: string;
  created_at_ms: number;
  note?: string;
  source_bytes: number;
};

// ── Listing, every page ────────────────────────────────────────────────────

async function pages<T>(path: string, field: string): Promise<T[]> {
  const out: T[] = [];
  let token: string | undefined;
  for (let i = 0; i < 100; i++) {
    const sep = path.includes("?") ? "&" : "?";
    const url = token ? `${path}${sep}pageToken=${encodeURIComponent(token)}` : path;
    const page = await get<Record<string, unknown>>(url);
    out.push(...((page[field] as T[]) ?? []));
    token = page["next-page-token"] as string | undefined;
    if (!token) break;
  }
  return out;
}

export const listNamespaces = (parent?: string[]) =>
  pages<string[]>(parent ? `/v1/namespaces?parent=${nsPath(parent)}` : "/v1/namespaces", "namespaces");
export const listTables = (ns: string[]) => pages<Ident>(`/v1/namespaces/${nsPath(ns)}/tables`, "identifiers");
export const listViews = (ns: string[]) => pages<Ident>(`/v1/namespaces/${nsPath(ns)}/views`, "identifiers");
export const loadTable = (ns: string[], name: string) =>
  get<LoadTable>(`/v1/namespaces/${nsPath(ns)}/tables/${encodeURIComponent(name)}`);
/** A table as this caller loads it, with the grade the server attached. */
export async function loadTableGraded(ns: string[], name: string): Promise<{ table: LoadTable; grade: Grade | undefined }> {
  const { data, headers } = await call<LoadTable>("GET", `/v1/namespaces/${nsPath(ns)}/tables/${encodeURIComponent(name)}`);
  return { table: data, grade: parseGrade(headers.get("rustberg-enforcement")) };
}

/** Who a preview is about. Always in the signed-in person's own tenant. */
export type Subject = { id: string; kind: "user" | "api_key"; roles: string[] };

export type Explain = {
  principal: { id: string; kind: string; tenant: string; roles: string[] };
  decision: "allow" | "deny";
  "matched-policies": string[];
  "read-restrictions"?: ReadRestrictions;
  refused?: string;
  enforcement?: { grade: Grade["grade"]; columns?: string[]; masked: boolean; header: string; remedy?: string };
  context: string;
};

/** What `subject` would be granted on a table — answered by the server's what-if, never computed here. */
export const explain = (ns: string[], name: string, subject: Subject) =>
  get<Explain>(
    `/management/v1/namespaces/${nsPath(ns)}/tables/${encodeURIComponent(name)}/explain?principal=${encodeURIComponent(subject.id)}&kind=${subject.kind}&roles=${encodeURIComponent(subject.roles.join(","))}`,
  );

/** One enumerated person a review checked. */
export type ImpactSubject = { kind: "api_key" | "user" | "group" | "anyone"; id: string; roles: string[] };
export type ImpactChange = {
  principal: ImpactSubject;
  resource: string;
  action: string;
  change: "gains" | "loses" | "restriction";
  before?: { grade: Grade["grade"]; header: string };
  after?: { grade: Grade["grade"]; header: string };
};
export type Impact = {
  checked: { principals: ImpactSubject[]; tables: number; evaluations: number; truncated: boolean; "unchecked-tables": number };
  changes: ImpactChange[];
  note: string;
};

/** What a candidate policy set would change, for whom — computed by the server's two authorizers. */
export const impact = async (source: string) =>
  (await call<Impact>("POST", "/management/v1/policies/impact", { source })).data;

export type AccessRow = {
  principal: ImpactSubject;
  access: "everything" | "filtered" | "masked" | "filtered-and-masked" | "nothing";
  grade?: { grade: Grade["grade"]; header: string };
  "matched-policies": string[];
};
/** Who of the principals the rules name may read a table, and in what form. */
export const tableAccess = (ns: string[], name: string) =>
  get<{ table: string; rows: AccessRow[]; note: string }>(
    `/management/v1/namespaces/${nsPath(ns)}/tables/${encodeURIComponent(name)}/access`,
  );

export const loadView = (ns: string[], name: string) =>
  get<LoadView>(`/v1/namespaces/${nsPath(ns)}/views/${encodeURIComponent(name)}`);
