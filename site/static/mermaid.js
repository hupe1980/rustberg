// Renders Mermaid diagrams, and only on pages that have one.
//
// Zola highlights a ```mermaid fence as source code, which is not useless — the
// source stays readable with JavaScript off, and that is the fallback. This
// upgrades it: the block's `textContent` is the original diagram (highlighting
// only wraps tokens in spans), so it can be handed straight to Mermaid.
//
// Mermaid is large and comes from a CDN, so it is loaded lazily and only when a
// diagram is actually present — every other page pays nothing.
(function () {
  "use strict";

  var blocks = Array.prototype.slice.call(
    document.querySelectorAll('pre > code[data-lang="mermaid"]')
  );
  if (!blocks.length) return;

  var VERSION = "11.4.1";
  var SRC = "https://cdn.jsdelivr.net/npm/mermaid@" + VERSION + "/dist/mermaid.esm.min.mjs";

  // Capture the source before replacing the markup: once the <pre> is gone the
  // diagram text is gone with it, and a failed render must leave the code block
  // in place rather than a blank space.
  var diagrams = blocks.map(function (code, index) {
    var pre = code.parentElement;
    var holder = document.createElement("div");
    holder.className = "mermaid";
    holder.id = "mermaid-" + index;
    holder.setAttribute("role", "img");
    pre.parentNode.insertBefore(holder, pre);
    pre.hidden = true;
    return { source: code.textContent, holder: holder, fallback: pre };
  });

  function isDark() {
    var explicit = document.documentElement.getAttribute("data-theme");
    if (explicit === "dark") return true;
    if (explicit === "light") return false;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  import(SRC)
    .then(function (module) {
      var mermaid = module.default;

      function draw() {
        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "strict",
          theme: isDark() ? "dark" : "default",
          fontFamily: "ui-sans-serif, system-ui, -apple-system, sans-serif",
        });

        diagrams.forEach(function (d, index) {
          mermaid
            .render("mmd-" + index + "-" + Date.now(), d.source)
            .then(function (result) {
              d.holder.innerHTML = result.svg;
              d.fallback.hidden = true;
            })
            .catch(function () {
              // A diagram that will not parse falls back to its source rather
              // than to nothing, so the page still carries the information.
              d.holder.remove();
              d.fallback.hidden = false;
            });
        });
      }

      draw();

      // Re-render on a theme change: Mermaid bakes colours into the SVG, so the
      // diagram would otherwise stay light on a dark page.
      var toggle = document.querySelector(".theme-toggle");
      if (toggle) toggle.addEventListener("click", function () { setTimeout(draw, 0); });
      window
        .matchMedia("(prefers-color-scheme: dark)")
        .addEventListener("change", draw);
    })
    .catch(function () {
      // Offline, or the CDN is blocked. Put the source back.
      diagrams.forEach(function (d) {
        d.holder.remove();
        d.fallback.hidden = false;
      });
    });
})();
