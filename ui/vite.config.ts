import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Flat names carrying a content hash: the binary embeds dist/ as it is and serves a file by its exact name
// or nothing (no directory walk to defend), and a new build's files have new names, so a browser holding
// an old one can never mix it into a new console. index.html is the only unhashed file. Served under /ui/.
const server = process.env.RUSTBERG_URL ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [svelte()],
  base: "/ui/",
  build: {
    outDir: "dist",
    assetsDir: "",
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
    target: ["safari17", "chrome120", "firefox128"],
    cssTarget: ["safari17", "chrome120", "firefox128"],
    rollupOptions: {
      output: { entryFileNames: "app-[hash].js", chunkFileNames: "[name]-[hash].js", assetFileNames: "[name]-[hash][extname]" },
    },
  },
  // `npm run dev`: the API comes from a running server (`cargo run -- --dev`).
  server: { proxy: { "/v1": server, "/auth": server, "/management": server } },
  // Components mount in tests, so Svelte must resolve its browser build there too; the contrast test
  // reads tokens.css as text, which vitest blanks unless the file is let through.
  test: { environment: "happy-dom", css: { include: [/tokens\.css/] } },
  resolve: process.env.VITEST ? { conditions: ["browser"] } : undefined,
});
