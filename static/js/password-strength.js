/* Password strength meter: Low / Medium / Good.
   Usage: put data-strength-input on the password <input> and add a
   .strength element (see change_password.html). */
(function () {
  var COMMON = ["password", "password1", "password123", "12345678", "123456789",
                "qwerty123", "iloveyou", "admin123", "welcome1", "abc12345"];

  function evaluate(pw) {
    var checks = {
      length: pw.length >= 8,
      mixed: /[a-z]/.test(pw) && /[A-Z]/.test(pw),
      number: /\d/.test(pw),
      symbol: /[^A-Za-z0-9]/.test(pw),
      long: pw.length >= 12
    };
    if (!pw) return { level: 0, label: "", checks: checks };
    if (!checks.length || COMMON.indexOf(pw.toLowerCase()) !== -1) {
      return { level: 1, label: "Low", checks: checks };
    }
    var points = (checks.mixed ? 1 : 0) + (checks.number ? 1 : 0) +
                 (checks.symbol ? 1 : 0) + (checks.long ? 1 : 0);
    if (points <= 1) return { level: 1, label: "Low", checks: checks };
    if (points === 2) return { level: 2, label: "Medium", checks: checks };
    return { level: 3, label: "Good", checks: checks };
  }

  document.addEventListener("DOMContentLoaded", function () {
    var input = document.querySelector("[data-strength-input]");
    var box = document.querySelector(".strength");
    if (!input || !box) return;

    var bars = box.querySelectorAll(".strength-bar span");
    var label = box.querySelector(".strength-label");
    var rules = box.querySelectorAll("[data-rule]");

    function update() {
      var r = evaluate(input.value);
      box.setAttribute("data-level", r.level);
      bars.forEach(function (b, i) { b.classList.toggle("on", i < r.level); });
      label.textContent = r.label ? "Password strength: " + r.label : "";
      rules.forEach(function (li) {
        li.classList.toggle("ok", !!r.checks[li.getAttribute("data-rule")]);
      });
    }
    input.addEventListener("input", update);
    update();

    var confirm = document.querySelector("[data-confirm-input]");
    var match = document.querySelector(".match-hint");
    if (confirm && match) {
      function checkMatch() {
        if (!confirm.value) { match.textContent = ""; match.className = "match-hint"; return; }
        var ok = confirm.value === input.value;
        match.textContent = ok ? "Passwords match" : "Passwords do not match";
        match.className = "match-hint " + (ok ? "ok" : "bad");
      }
      confirm.addEventListener("input", checkMatch);
      input.addEventListener("input", checkMatch);
    }
  });
})();