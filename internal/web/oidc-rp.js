(function () {
  var issuerMeta = document.querySelector('meta[name="oidc-issuer"]');
  var clientMeta = document.querySelector('meta[name="oidc-client-id"]');
  var issuer = ((issuerMeta && issuerMeta.content) || "").replace(/\/$/, "");
  var clientId = (clientMeta && clientMeta.content) || "oidc-rp";
  var redirectUri = window.location.origin + "/oidc-rp";
  var storage = window.sessionStorage;

  var KEY_VERIFIER = "oidc_rp_verifier";
  var KEY_STATE = "oidc_rp_state";
  var KEY_NONCE = "oidc_rp_nonce";
  var KEY_TOKENS = "oidc_rp_tokens";

  var signedOut = document.getElementById("signed-out");
  var signedIn = document.getElementById("signed-in");
  var message = document.getElementById("message");
  var userinfoEl = document.getElementById("userinfo");
  var idTokenEl = document.getElementById("id-token");

  function showMessage(text, type) {
    message.textContent = text;
    message.hidden = !text;
    message.className = "message" + (type ? " " + type : "");
  }

  function randomString(bytes) {
    var buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return base64url(buf);
  }

  function base64url(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeJwtPayload(token) {
    var parts = (token || "").split(".");
    if (parts.length < 2) return null;
    var json = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    while (json.length % 4) json += "=";
    try {
      return JSON.parse(atob(json));
    } catch (e) {
      return null;
    }
  }

  async function sha256Base64Url(str) {
    var data = new TextEncoder().encode(str);
    var hash = await crypto.subtle.digest("SHA-256", data);
    return base64url(new Uint8Array(hash));
  }

  function readTokens() {
    try {
      var raw = storage.getItem(KEY_TOKENS);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function writeTokens(tokens) {
    storage.setItem(KEY_TOKENS, JSON.stringify(tokens));
  }

  function clearAuth() {
    storage.removeItem(KEY_TOKENS);
    storage.removeItem(KEY_VERIFIER);
    storage.removeItem(KEY_STATE);
    storage.removeItem(KEY_NONCE);
  }

  async function startLogin(prompt) {
    showMessage("");
    var verifier = randomString(32);
    var challenge = await sha256Base64Url(verifier);
    var state = randomString(16);
    var nonce = randomString(16);
    storage.setItem(KEY_VERIFIER, verifier);
    storage.setItem(KEY_STATE, state);
    storage.setItem(KEY_NONCE, nonce);

    var params = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid email profile offline_access",
      state: state,
      nonce: nonce,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    if (prompt) params.set("prompt", prompt);
    window.location.assign(issuer + "/authorize?" + params.toString());
  }

  async function tokenRequest(body) {
    var res = await fetch(issuer + "/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });
    var text = await res.text();
    var data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      throw new Error(text || "Token request failed");
    }
    if (!res.ok) {
      throw new Error(data.error_description || data.error || "Token request failed");
    }
    return data;
  }

  async function exchangeCode(code, state) {
    var expected = storage.getItem(KEY_STATE);
    var verifier = storage.getItem(KEY_VERIFIER);
    if (!expected || state !== expected) {
      throw new Error("Invalid state");
    }
    if (!verifier) {
      throw new Error("Missing PKCE verifier");
    }
    var tokens = await tokenRequest(new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier
    }));
    storage.removeItem(KEY_VERIFIER);
    storage.removeItem(KEY_STATE);
    writeTokens(tokens);
    return tokens;
  }

  async function loadUserInfo(accessToken) {
    var res = await fetch(issuer + "/userinfo", {
      headers: { Authorization: "Bearer " + accessToken }
    });
    var data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || "UserInfo failed");
    }
    return data;
  }

  async function render(tokens) {
    if (!tokens || !tokens.access_token) {
      signedOut.hidden = false;
      signedIn.hidden = true;
      return;
    }
    signedOut.hidden = true;
    signedIn.hidden = false;
    idTokenEl.textContent = JSON.stringify(decodeJwtPayload(tokens.id_token), null, 2);
    try {
      var info = await loadUserInfo(tokens.access_token);
      userinfoEl.textContent = JSON.stringify(info, null, 2);
    } catch (e) {
      userinfoEl.textContent = e.message;
    }
  }

  async function refreshTokens() {
    var tokens = readTokens();
    if (!tokens || !tokens.refresh_token) {
      showMessage("No refresh token. Sign in with offline_access.", "error");
      return;
    }
    try {
      var next = await tokenRequest(new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        client_id: clientId
      }));
      writeTokens(next);
      showMessage("Tokens refreshed.", "success");
      await render(next);
    } catch (e) {
      showMessage(e.message, "error");
    }
  }

  function logout() {
    var tokens = readTokens() || {};
    clearAuth();
    var params = new URLSearchParams({
      post_logout_redirect_uri: redirectUri,
      client_id: clientId
    });
    if (tokens.id_token) params.set("id_token_hint", tokens.id_token);
    window.location.assign(issuer + "/end_session?" + params.toString());
  }

  document.getElementById("login-btn").addEventListener("click", function () {
    startLogin("");
  });
  document.getElementById("login-prompt-btn").addEventListener("click", function () {
    startLogin("login");
  });
  document.getElementById("refresh-btn").addEventListener("click", refreshTokens);
  document.getElementById("logout-btn").addEventListener("click", logout);

  async function init() {
    if (!issuer) {
      showMessage("OIDC issuer is not configured.", "error");
      return;
    }
    var qs = new URLSearchParams(window.location.search);
    if (qs.get("error")) {
      showMessage((qs.get("error") + ": " + (qs.get("error_description") || "")).trim(), "error");
      history.replaceState({}, "", "/oidc-rp");
      await render(readTokens());
      return;
    }
    if (qs.get("code")) {
      try {
        var tokens = await exchangeCode(qs.get("code"), qs.get("state"));
        history.replaceState({}, "", "/oidc-rp");
        showMessage("Signed in.", "success");
        await render(tokens);
      } catch (e) {
        showMessage(e.message, "error");
        history.replaceState({}, "", "/oidc-rp");
        await render(null);
      }
      return;
    }
    await render(readTokens());
  }

  init();
})();
