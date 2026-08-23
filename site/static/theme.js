// Progressive enhancements. Everything here is optional: with JavaScript off the
// site is a readable, navigable document, and the only losses are the theme
// toggle, search, and the highlighted table-of-contents entry.
(function () {
  "use strict";

  // ── Theme toggle ──────────────────────────────────────────────────────────
  //
  // Three states, not two. "auto" is the default and follows the OS; clicking
  // moves to the opposite of whatever is currently *shown*, which is what a
  // reader expects from a single button.
  var root = document.documentElement;
  var toggle = document.querySelector(".theme-toggle");

  function shown() {
    var explicit = root.getAttribute("data-theme");
    if (explicit === "light" || explicit === "dark") return explicit;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = shown() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("rb-theme", next); } catch (e) {}
    });
  }

  // ── Wide tables scroll inside their own box ───────────────────────────────
  //
  // A reference page has tables wider than the column. Wrapping them here rather
  // than in the Markdown keeps the source portable, and stops the whole page
  // scrolling sideways on a phone.
  document.querySelectorAll(".doc__body table").forEach(function (table) {
    if (table.parentElement && table.parentElement.classList.contains("table-wrap")) return;
    var wrap = document.createElement("div");
    wrap.className = "table-wrap";
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
  });

  // ── Heading anchors ───────────────────────────────────────────────────────
  //
  // Every h2/h3 gets a link to itself, so a reader can cite a specific claim.
  document.querySelectorAll(".doc__body > h2[id], .doc__body > h3[id]").forEach(function (h) {
    var a = document.createElement("a");
    a.className = "anchor";
    a.href = "#" + h.id;
    a.setAttribute("aria-label", "Link to this section");
    a.textContent = "#";
    h.appendChild(a);
  });

  // ── Table of contents: highlight the section being read ───────────────────
  var links = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (links.length && "IntersectionObserver" in window) {
    var byId = {};
    links.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });

    var visible = new Set();
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) visible.add(entry.target.id);
        else visible.delete(entry.target.id);
      });

      // The first heading still on screen, in document order — not the last one
      // to fire, which jumps around when several cross the boundary at once.
      var current = null;
      for (var i = 0; i < links.length; i++) {
        var id = links[i].getAttribute("href").slice(1);
        if (visible.has(id)) { current = id; break; }
      }
      links.forEach(function (a) { a.classList.remove("is-active"); });
      if (current && byId[current]) byId[current].classList.add("is-active");
    }, { rootMargin: "-70px 0px -70% 0px" });

    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) observer.observe(el);
    });
  }
})();
