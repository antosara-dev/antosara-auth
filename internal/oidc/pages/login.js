(function () {
  var form = document.getElementById("login-form");
  if (!form) return;
  form.addEventListener("submit", function () {
    var btn = document.getElementById("submit-btn");
    if (btn) btn.disabled = true;
  });
})();
