<script lang="ts" module>
  // Monochrome glyphs in the spirit of SF Symbols (1.6 stroke on a 20-point grid), drawn for this
  // project — not Apple's. Decorative by default: the word next to a symbol carries the meaning.
  const paths: Record<string, string> = {
    catalog: "M4 5.5c0-1.4 2.7-2.5 6-2.5s6 1.1 6 2.5-2.7 2.5-6 2.5-6-1.1-6-2.5z M4 5.5v9c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5v-9 M4 10c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5",
    folder: "M3 6a1.5 1.5 0 0 1 1.5-1.5h3.3l1.6 1.8h6.1A1.5 1.5 0 0 1 17 7.8v6.7a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 3 14.5z",
    table: "M3.5 4.5h13v11h-13z M3.5 8.2h13 M3.5 11.8h13 M8 8.2v7.3",
    view: "M2.5 10s2.8-5 7.5-5 7.5 5 7.5 5-2.8 5-7.5 5-7.5-5-7.5-5z M10 12.3a2.3 2.3 0 1 0 0-4.6 2.3 2.3 0 0 0 0 4.6z",
    shield: "M10 2.8l6 2.2v4.6c0 3.7-2.5 6.3-6 7.6-3.5-1.3-6-3.9-6-7.6V5z",
    "shield-check": "M10 2.8l6 2.2v4.6c0 3.7-2.5 6.3-6 7.6-3.5-1.3-6-3.9-6-7.6V5z M7.3 10l2 2 3.6-3.8",
    policy: "M5.5 2.8h6l3 3v11.4h-9z M11.5 2.8v3h3 M7.8 10h4.4 M7.8 13h3",
    versions: "M10 16.5a6.5 6.5 0 1 0-6.2-8.5 M3.5 4.2V8h3.8 M10 6.5V10l2.5 1.6",
    person: "M10 9.6a3.1 3.1 0 1 0 0-6.2 3.1 3.1 0 0 0 0 6.2z M4 16.8c.6-3 3-4.8 6-4.8s5.4 1.8 6 4.8",
    plug: "M7 3v4 M13 3v4 M5.5 7h9v2.5a4.5 4.5 0 0 1-9 0z M10 14v3",
    lock: "M5.5 9h9v7.5h-9z M7 9V6.5a3 3 0 0 1 6 0V9",
    key: "M12.5 10.3a3.8 3.8 0 1 0-3.4-2.1L3.5 13.8V16.5h2.7v-1.7h1.7v-1.7h1.6l1.4-1.4c.5.4 1 .6 1.6.6z M13.6 6.4h0",
    eye: "M2.5 10s2.8-5 7.5-5 7.5 5 7.5 5-2.8 5-7.5 5-7.5-5-7.5-5z M10 12.3a2.3 2.3 0 1 0 0-4.6 2.3 2.3 0 0 0 0 4.6z",
    "eye-slash": "M4 4l12 12 M8.2 5.3A7.6 7.6 0 0 1 10 5c4.7 0 7.5 5 7.5 5a12.8 12.8 0 0 1-2.4 2.9 M5.3 6.9A12.6 12.6 0 0 0 2.5 10s2.8 5 7.5 5c1 0 2-.2 2.9-.6",
    filter: "M3.5 4.5h13l-5 6v5l-3 1.5v-6.5z",
    search: "M8.8 14.2a5.4 5.4 0 1 0 0-10.8 5.4 5.4 0 0 0 0 10.8z M12.8 12.8l3.7 3.7",
    copy: "M7 7h8.5v9.5H7z M4.5 13V3.5H13",
    check: "M4.5 10.5l3.5 3.5 7.5-8",
    xmark: "M5.5 5.5l9 9 M14.5 5.5l-9 9",
    warning: "M10 3.5l7 12.5H3z M10 8.5v3.5 M10 14.3h0",
    chevron: "M6 8l4 4 4-4",
    "chevron-right": "M8 6l4 4-4 4",
    pencil: "M12.8 4.2l3 3L7.5 15.5 4 16l.5-3.5z M11 6l3 3",
    restore: "M4.5 10a5.5 5.5 0 1 0 1.6-3.9 M4.5 3.5V7H8",
    signout: "M8 4.5H4.5v11H8 M11.5 6.5L15 10l-3.5 3.5 M15 10H7.5",
    inspector: "M3.5 4.5h13v11h-13z M12 4.5v11",
    snapshot: "M3.5 6.5h3l1.3-2h4.4l1.3 2h3v9h-13z M10 13.2a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z",
    partition: "M3.5 4.5h13v11h-13z M8 4.5v11 M12 4.5v11",
    info: "M10 17a7 7 0 1 0 0-14 7 7 0 0 0 0 14z M10 9v4.5 M10 6.6h0",
    plus: "M10 4v12 M4 10h12",
  };
  export type SymbolName = keyof typeof paths;
  export const symbolNames = Object.keys(paths);
</script>

<script lang="ts">
  let {
    name,
    size = 16,
    label = undefined,
    weight = 1.6,
  }: { name: string; size?: number; label?: string; weight?: number } = $props();
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 20 20"
  fill="none"
  stroke="currentColor"
  stroke-width={weight}
  stroke-linecap="round"
  stroke-linejoin="round"
  role={label ? "img" : undefined}
  aria-label={label}
  aria-hidden={label ? undefined : "true"}
>
  <path d={paths[name] ?? ""} />
</svg>

<style>
  svg {
    flex: none;
    display: block;
  }
</style>
