// A line diff: the longest common subsequence, then the edits around it. Policy files are short, so the
// quadratic table is fine and there is nothing to configure.
export type DiffLine = { kind: "same" | "add" | "del"; text: string; old?: number; new?: number };

export function diff(before: string, after: string): DiffLine[] {
  const a = before.split("\n");
  const b = after.split("\n");
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i]!, old: i + 1, new: j + 1 });
      i++;
      j++;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      out.push({ kind: "del", text: a[i]!, old: i + 1 });
      i++;
    } else {
      out.push({ kind: "add", text: b[j]!, new: j + 1 });
      j++;
    }
  }
  for (; i < n; i++) out.push({ kind: "del", text: a[i]!, old: i + 1 });
  for (; j < m; j++) out.push({ kind: "add", text: b[j]!, new: j + 1 });
  return out;
}

export function changes(lines: DiffLine[]): { added: number; removed: number } {
  return {
    added: lines.filter((l) => l.kind === "add").length,
    removed: lines.filter((l) => l.kind === "del").length,
  };
}

// Unchanged runs longer than the context on either side of a change collapse into one fold, so a
// one-line edit to a long policy reads as one line plus its surroundings.
export type Fold = { kind: "fold"; lines: DiffLine[] };

export function fold(lines: DiffLine[], context = 3): (DiffLine | Fold)[] {
  if (lines.every((l) => l.kind === "same")) return lines;
  const near = lines.map(() => false);
  lines.forEach((l, i) => {
    if (l.kind === "same") return;
    for (let k = Math.max(0, i - context); k <= Math.min(lines.length - 1, i + context); k++) near[k] = true;
  });
  const out: (DiffLine | Fold)[] = [];
  let run: DiffLine[] = [];
  const flush = () => {
    if (run.length > 1) out.push({ kind: "fold", lines: run });
    else out.push(...run);
    run = [];
  };
  lines.forEach((l, i) => {
    if (near[i]) {
      flush();
      out.push(l);
    } else run.push(l);
  });
  flush();
  return out;
}
