package oidc

import (
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	raw := bearerToken(r)
	if raw == "" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		raw = strings.TrimSpace(r.Form.Get("access_token"))
	}
	if raw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	tok, err := h.signer.parse(raw)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	if !isOIDCAccessToken(tok) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	sub := tok.Subject()
	user, err := h.users.GetUserByEmail(r.Context(), sub)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	scope := ""
	if v, ok := tok.Get("scope"); ok {
		scope, _ = v.(string)
	}
	scopes := splitScopes(scope)

	claims := map[string]any{"sub": user.Email}
	if hasScope(scopes, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.Verified
	}
	if hasScope(scopes, "profile") {
		name := user.Alias
		if name == "" {
			name = user.Email
		}
		claims["name"] = name
		claims["preferred_username"] = name
	}
	writeJSON(w, http.StatusOK, claims)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

func isOIDCAccessToken(tok jwt.Token) bool {
	if tok.Issuer() != issuer() {
		return false
	}
	use, _ := tok.Get("token_use")
	if use != "access" {
		return false
	}
	for _, a := range tok.Audience() {
		if a == issuer() {
			return true
		}
	}
	return false
}
