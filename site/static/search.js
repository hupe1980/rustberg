// Client-side documentation search over Zola's elasticlunr index.
//
// The index ships as a static file, so search needs no server and keeps working
// on GitHub Pages. It is loaded with `defer` alongside the page, and the input
// stays inert until it is ready rather than silently doing nothing.
(function () {
  "use strict";

  var input = document.getElementById("search-input");
  var results = document.getElementById("search-results");
  if (!input || !results) return;

  var index = null;

  function ready() {
    if (index) return true;
    if (typeof window.elasticlunr === "undefined" || typeof window.searchIndex === "undefined") {
      return false;
    }
    index = window.elasticlunr.Index.load(window.searchIndex);
    return true;
  }

  function close() {
    results.hidden = true;
    results.innerHTML = "";
  }

  // Trim a body excerpt to the first place the query actually appears, so the
  // preview shows why the page matched rather than its opening sentence.
  function excerpt(body, query) {
    if (!body) return "";
    var at = body.toLowerCase().indexOf(query.toLowerCase());
    var start = at > 60 ? at - 60 : 0;
    var text = body.slice(start, start + 160).replace(/\s+/g, " ").trim();
    return (start > 0 ? "…" : "") + text + "…";
  }

  function render(hits, query) {
    if (!hits.length) {
      results.innerHTML = '<p class="search__empty">No matches for “' +
        query.replace(/[<>&]/g, "") + '”.</p>';
      results.hidden = false;
      return;
    }

    results.innerHTML = hits.slice(0, 8).map(function (hit) {
      var doc = hit.doc;
      var a = document.createElement("a");
      a.className = "search__hit";
      a.href = doc.id;
      var title = document.createElement("strong");
      title.textContent = doc.title;
      var context = document.createElement("span");
      context.textContent = excerpt(doc.body, query);
      a.appendChild(title);
      a.appendChild(context);
      return a.outerHTML;
    }).join("");
    results.hidden = false;
  }

  var timer = null;
  input.addEventListener("input", function () {
    clearTimeout(timer);
    timer = setTimeout(function () {
      var query = input.value.trim();
      if (query.length < 2) return close();
      if (!ready()) return close();

      render(index.search(query, {
        bool: "AND",
        expand: true,
        fields: {
          title: { boost: 3 },
          description: { boost: 2 },
          body: { boost: 1 },
        },
      }), query);
    }, 120);
  });

  input.addEventListener("keydown", function (event) {
    if (event.key === "Escape") { input.value = ""; close(); input.blur(); }
    if (event.key === "ArrowDown") {
      var first = results.querySelector(".search__hit");
      if (first) { event.preventDefault(); first.focus(); }
    }
  });

  document.addEventListener("click", function (event) {
    if (!results.contains(event.target) && event.target !== input) close();
  });

  // `/` focuses search, the convention every documentation site shares.
  document.addEventListener("keydown", function (event) {
    if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
    var tag = (event.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || event.target.isContentEditable) return;
    event.preventDefault();
    input.focus();
  });
})();
