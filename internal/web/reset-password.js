(function () {
  var tokenInput = document.getElementById("token");
  var form = document.getElementById("reset-form");
  var message = document.getElementById("message");
  var submitBtn = document.getElementById("submit-btn");

  function showMessage(text, type) {
    message.textContent = text;
    message.hidden = false;
    message.className = "message " + type;
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    var token = tokenInput.value.trim();
    var password = document.getElementById("password").value;

    if (!token) {
      showMessage("Missing reset token. Open the link from your password reset email.", "error");
      return;
    }

    submitBtn.disabled = true;
    message.hidden = true;

    fetch("/api/reset-password/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token, password: password })
    })
      .then(function (response) {
        return response.text().then(function (body) {
          return { ok: response.ok, body: body };
        });
      })
      .then(function (result) {
        if (result.ok) {
          showMessage(result.body || "Password has been reset successfully.", "success");
          form.reset();
          tokenInput.value = token;
        } else {
          showMessage(result.body || "Failed to reset password.", "error");
        }
      })
      .catch(function () {
        showMessage("Network error. Is the auth service running?", "error");
      })
      .finally(function () {
        submitBtn.disabled = false;
      });
  });
})();
