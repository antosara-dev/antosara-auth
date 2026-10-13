package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

func randomToken(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Raw(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return computed == challenge
}

func splitScopes(scope string) []string {
	parts := strings.Fields(scope)
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

func filterSupportedScopes(requested []string) ([]string, error) {
	supported := map[string]struct{}{
		"openid":         {},
		"profile":        {},
		"email":          {},
		"offline_access": {},
	}
	var out []string
	hasOpenID := false
	for _, s := range requested {
		if _, ok := supported[s]; !ok {
			continue
		}
		if s == "openid" {
			hasOpenID = true
		}
		out = append(out, s)
	}
	if !hasOpenID {
		return nil, fmt.Errorf("scope must contain openid")
	}
	return out, nil
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func parsePrompt(raw string) (login, consent, none bool, err error) {
	if strings.TrimSpace(raw) == "" {
		return false, false, false, nil
	}
	for _, p := range strings.Fields(raw) {
		switch p {
		case "login":
			login = true
		case "consent":
			consent = true
		case "none":
			none = true
		case "select_account":
			login = true
		default:
			return false, false, false, fmt.Errorf("unsupported prompt value")
		}
	}
	if none && (login || consent) {
		return false, false, false, fmt.Errorf("prompt none cannot be combined with other values")
	}
	return login, consent, none, nil
}
