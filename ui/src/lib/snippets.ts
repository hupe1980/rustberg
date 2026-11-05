// "Connect a client": the published client docs' snippets, with this server's address filled in. An API
// key is a bearer token, so every client gets it as `token`.
export type Snippet = {
  id: string;
  title: string;
  language: string;
  code: (uri: string, token: string, warehouse: string) => string;
};

export const snippets: Snippet[] = [
  {
    id: "pyiceberg",
    title: "PyIceberg",
    language: "python",
    code: (uri, token) => `from pyiceberg.catalog import load_catalog

catalog = load_catalog("rustberg", **{
    "uri": "${uri}",
    "token": "${token}",
})
print(catalog.list_namespaces())`,
  },
  {
    id: "spark",
    title: "Spark",
    language: "python",
    code: (uri, token) => `spark = SparkSession.builder \\
    .config("spark.sql.catalog.rustberg", "org.apache.iceberg.spark.SparkCatalog") \\
    .config("spark.sql.catalog.rustberg.type", "rest") \\
    .config("spark.sql.catalog.rustberg.uri", "${uri}") \\
    .config("spark.sql.catalog.rustberg.token", "${token}") \\
    .getOrCreate()`,
  },
  {
    id: "trino",
    title: "Trino",
    language: "properties",
    code: (uri, token) => `connector.name=iceberg
iceberg.catalog.type=rest
iceberg.rest-catalog.uri=${uri}
iceberg.rest-catalog.security=OAUTH2
iceberg.rest-catalog.oauth2.token=${token}`,
  },
  {
    id: "duckdb",
    title: "DuckDB",
    language: "sql",
    // DuckDB takes a bearer token through a secret, and attaches by the server's warehouse.
    code: (uri, token, warehouse) => `INSTALL iceberg; LOAD iceberg;
CREATE SECRET rustberg (TYPE iceberg, TOKEN '${token}');
ATTACH '${warehouse}' AS rustberg (TYPE iceberg, SECRET rustberg, ENDPOINT '${uri}');
SHOW ALL TABLES;`,
  },
];

/** A credential as shown before it is revealed: enough to recognise, not enough to use. */
export function masked(token: string): string {
  if (token.length <= 8) return "•".repeat(token.length);
  return `${token.slice(0, 4)}${"•".repeat(12)}${token.slice(-4)}`;
}
