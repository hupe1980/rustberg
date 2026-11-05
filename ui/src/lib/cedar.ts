// Quiet emphasis for Cedar: keywords, annotations, strings, comments. Tokens are rendered as text nodes,
// never as HTML, so a policy can contain anything without becoming markup.
export type Token = { kind: "kw" | "ann" | "str" | "com" | "txt"; text: string };

const KEYWORDS = new Set([
  "permit", "forbid", "when", "unless", "principal", "action", "resource", "context",
  "in", "has", "like", "is", "if", "then", "else", "true", "false",
]);

export function tokenize(line: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  let plain = "";
  const flush = () => {
    if (plain) out.push({ kind: "txt", text: plain });
    plain = "";
  };
  while (i < line.length) {
    const rest = line.slice(i);
    if (rest.startsWith("//")) {
      flush();
      out.push({ kind: "com", text: rest });
      break;
    }
    const ch = line[i]!;
    if (ch === '"') {
      flush();
      let j = i + 1;
      while (j < line.length && line[j] !== '"') j += line[j] === "\\" ? 2 : 1;
      out.push({ kind: "str", text: line.slice(i, Math.min(j + 1, line.length)) });
      i = j + 1;
      continue;
    }
    const word = /^@?[A-Za-z_][A-Za-z0-9_]*/.exec(rest);
    if (word) {
      const w = word[0];
      if (w.startsWith("@")) {
        flush();
        out.push({ kind: "ann", text: w });
      } else if (KEYWORDS.has(w)) {
        flush();
        out.push({ kind: "kw", text: w });
      } else {
        plain += w;
      }
      i += w.length;
      continue;
    }
    plain += ch;
    i++;
  }
  flush();
  return out;
}
