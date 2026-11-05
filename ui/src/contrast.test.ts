// SC-003, the half a DOM without layout cannot check: every text colour the console uses, on every
// surface it sits on, in light and dark, read from tokens.css itself — so a token edit that drops
// below WCAG AA fails here rather than in someone's eyes.
import { describe, expect, it } from "vitest";
import css from "./tokens.css?raw";

function block(selector: RegExp): Record<string, string> {
  const m = css.match(selector);
  if (!m) throw new Error(`no block ${selector}`);
  return Object.fromEntries([...m[1]!.matchAll(/--([a-z0-9-]+):\s*([^;]+);/g)].map((x) => [x[1]!, x[2]!.trim()]));
}
const light = block(/^:root \{([\s\S]*?)\n\}/m);
const dark = { ...light, ...block(/@media \(prefers-color-scheme: dark\) \{\s*:root \{([\s\S]*?)\}/) };

type RGBA = [number, number, number, number];
function parse(v: string): RGBA {
  const hex = v.match(/^#([0-9a-f]{6})$/i);
  if (hex) return [0, 2, 4].map((i) => parseInt(hex[1]!.slice(i, i + 2), 16)).concat(1) as RGBA;
  const rgba = v.match(/^rgba?\(([^)]+)\)$/);
  if (rgba) {
    const [r, g, b, a = "1"] = rgba[1]!.split(",").map((s) => s.trim());
    return [Number(r), Number(g), Number(b), Number(a)];
  }
  throw new Error(`not a colour: ${v}`);
}
const over = ([r, g, b, a]: RGBA, [R, G, B]: RGBA): RGBA => [r * a + R * (1 - a), g * a + G * (1 - a), b * a + B * (1 - a), 1];
const lum = ([r, g, b]: RGBA) =>
  [r, g, b]
    .map((c) => c / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
    .reduce((s, c, i) => s + c * [0.2126, 0.7152, 0.0722][i]!, 0);
function ratio(tokens: Record<string, string>, fg: string, ...layers: string[]): number {
  const base = layers.map((l) => parse(tokens[l]!)).reduceRight((under, top) => over(top, under));
  const a = lum(over(parse(tokens[fg]!), base));
  const b = lum(base);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

// Body text: 4.5:1. Each pair is [foreground, ...layers from top to the opaque surface]. `faint` is
// absent on purpose: it draws only aria-hidden gutters (line numbers) and the loading glyph, never text.
const text: string[][] = [
  ...["text", "text-2", "muted", "accent-ink", "allowed", "restricted", "denied"].flatMap((t) => [
    [t, "bg"],
    [t, "surface"],
  ]),
  ["accent-ink", "accent-soft", "surface"],
  ["allowed", "allowed-soft", "surface"],
  ["restricted", "restricted-soft", "surface"],
  ["denied", "denied-soft", "surface"],
  ...["code-keyword", "code-annotation", "code-string", "code-comment", "text"].flatMap((t) => [
    [t, "surface"],
    [t, "diff-add", "surface"],
    [t, "diff-del", "surface"],
  ]),
];

describe.each([
  ["light", light],
  ["dark", dark],
])("%s", (_, tokens) => {
  it.each(text)("%s on %s meets 4.5:1", (fg, ...layers) => {
    expect(ratio(tokens, fg!, ...layers)).toBeGreaterThanOrEqual(4.5);
  });
});
