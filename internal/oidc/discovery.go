package oidc

import (
	"encoding/json"
	"net/http"
)

func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	iss := issuer()
	doc := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"end_session_endpoint":                  iss + "/end_session",
		"jwks_uri":                              jwksURI(),
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{GrantAuthorizationCode, GrantRefreshToken},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{AuthMethodBasic, AuthMethodPost, AuthMethodNone},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "preferred_username",
		},
		"prompt_values_supported": []string{"login", "consent", "none"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}
