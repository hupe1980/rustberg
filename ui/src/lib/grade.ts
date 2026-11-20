// The `Rustberg-Enforcement` header, read — never computed. An RFC 9651 Item: a token, then parameters:
// `none`, `architectural`, or `cooperative;columns="region,ts";masked`.

export type Grade = { grade: "none" | "architectural" | "cooperative"; columns: string[]; masked: boolean };

/** Parses the header; `undefined` for an absent or unrecognised value, which the console then does not claim. */
export function parseGrade(header: string | null | undefined): Grade | undefined {
  if (!header) return undefined;
  const [token, ...params] = splitParams(header.trim());
  if (token !== "none" && token !== "architectural" && token !== "cooperative") return undefined;
  const grade: Grade = { grade: token, columns: [], masked: false };
  for (const param of params) {
    const eq = param.indexOf("=");
    const key = (eq < 0 ? param : param.slice(0, eq)).trim();
    const value = eq < 0 ? "" : param.slice(eq + 1).trim();
    if (key === "masked") grade.masked = value === "" || value === "?1";
    if (key === "columns") grade.columns = unquote(value).split(",").filter(Boolean);
  }
  return grade;
}

/** Splits on `;` outside quotes. */
function splitParams(value: string): string[] {
  const out: string[] = [];
  let current = "";
  let quoted = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '"' && value[i - 1] !== "\\") quoted = !quoted;
    if (c === ";" && !quoted) {
      out.push(current);
      current = "";
    } else current += c;
  }
  out.push(current);
  return out;
}

/** An sf-string (`"a\"b"`) or a Display String (`%"r%c3%a9gion"`). */
function unquote(value: string): string {
  if (value.startsWith('%"') && value.endsWith('"')) {
    const bytes: number[] = [];
    const body = value.slice(2, -1);
    for (let i = 0; i < body.length; i++) {
      if (body[i] === "%") {
        bytes.push(parseInt(body.slice(i + 1, i + 3), 16));
        i += 2;
      } else bytes.push(body.charCodeAt(i));
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
  }
  if (value.startsWith('"') && value.endsWith('"')) return value.slice(1, -1).replace(/\\(["\\])/g, "$1");
  return value;
}

/** One sentence, for a person: how strongly what is withheld from them holds. */
export function strength(grade: Grade, names?: (c: string) => string): { title: string; detail: string } {
  const list = (xs: string[]) => xs.map((x) => (names ? names(x) : x)).join(", ");
  if (grade.grade === "architectural")
    return {
      title: "Holds against any engine",
      detail: "No file handed over holds a row outside the filter, so nothing depends on the engine applying it.",
    };
  if (grade.grade === "cooperative") {
    const why: string[] = [];
    if (grade.columns.length) why.push(`files also hold rows outside the filter on ${list(grade.columns)}`);
    if (grade.masked) why.push("files hold masked columns unmasked");
    return {
      title: "Holds only in an engine that applies it",
      detail: `The ${why.join(", and ")} — a cooperating engine withholds them; one reading the files directly would not.`,
    };
  }
  return { title: "Nothing is withheld", detail: "No restriction applies." };
}
