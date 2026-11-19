(function () {
  const root = document.documentElement;
  const STORAGE_KEY = "ledgerline-theme";

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) { /* ignore */ }
  }

  let saved = null;
  try { saved = localStorage.getItem(STORAGE_KEY); } catch (e) { /* ignore */ }

  if (saved) {
    applyTheme(saved);
  } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
    applyTheme("dark");
  }

  document.addEventListener("DOMContentLoaded", function () {
    const toggles = document.querySelectorAll("#theme-toggle");
    toggles.forEach(function (btn) {
      btn.addEventListener("click", function () {
        const current = root.getAttribute("data-theme") || "light";
        applyTheme(current === "dark" ? "light" : "dark");
      });
    });
  });
})();

// Copy-to-clipboard buttons: <button data-copy="text">Copy</button>
(function () {
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (!btn) return;
    var text = btn.getAttribute("data-copy");
    var done = function () {
      var old = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(function () { btn.textContent = old; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done);
    } else {
      var t = document.createElement("textarea");
      t.value = text; document.body.appendChild(t); t.select();
      try { document.execCommand("copy"); done(); } catch (err) {}
      document.body.removeChild(t);
    }
  });
})();