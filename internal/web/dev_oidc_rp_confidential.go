package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/antosara-dev/antosara-auth/internal/oidc"
	"github.com/go-chi/chi/v5"
)

const (
	cookieVerifier = "oidc_rp_c_verifier"
	cookieState    = "oidc_rp_c_state"
	cookieNonce    = "oidc_rp_c_nonce"
	cookieIDToken  = "oidc_rp_c_id_token"
)

func registerConfidentialRP(r chi.Router, issuer string) {
	r.Get("/oidc-rp/confidential", confidentialStart(issuer))
	r.Get("/oidc-rp/callback", confidentialCallback(issuer))
	r.Get("/oidc-rp/confidential/logout", confidentialLogout(issuer))
}

func confidentialStart(issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		verifier, err := randomB64(32)
		if err != nil {
			http.Error(w, "Unable to start login", http.StatusInternalServerError)
			return
		}
		state, err := randomB64(16)
		if err != nil {
			http.Error(w, "Unable to start login", http.StatusInternalServerError)
			return
		}
		nonce, err := randomB64(16)
		if err != nil {
			http.Error(w, "Unable to start login", http.StatusInternalServerError)
			return
		}
		setRPCookie(w, cookieVerifier, verifier, 600)
		setRPCookie(w, cookieState, state, 600)
		setRPCookie(w, cookieNonce, nonce, 600)

		redirectURI := requestOrigin(r) + "/oidc-rp/callback"
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {oidc.DevRPConfidentialClientID},
			"redirect_uri":          {redirectURI},
			"scope":                 {"openid email profile offline_access"},
			"state":                 {state},
			"nonce":                 {nonce},
			"code_challenge":        {pkceChallenge(verifier)},
			"code_challenge_method": {"S256"},
		}
		if prompt := strings.TrimSpace(r.URL.Query().Get("prompt")); prompt != "" {
			q.Set("prompt", prompt)
		}
		http.Redirect(w, r, issuer+"/authorize?"+q.Encode(), http.StatusFound)
	}
}

func confidentialCallback(issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if errCode := q.Get("error"); errCode != "" {
			writeConfidentialPage(w, http.StatusBadRequest, errCode+": "+q.Get("error_description"), "", "")
			return
		}

		stateCookie, _ := r.Cookie(cookieState)
		verifierCookie, _ := r.Cookie(cookieVerifier)
		if stateCookie == nil || verifierCookie == nil || q.Get("state") != stateCookie.Value {
			writeConfidentialPage(w, http.StatusBadRequest, "Invalid or expired login state. Start again from the test app.", "", "")
			return
		}
		clearRPCookie(w, cookieState)
		clearRPCookie(w, cookieVerifier)
		clearRPCookie(w, cookieNonce)

		redirectURI := requestOrigin(r) + "/oidc-rp/callback"
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {q.Get("code")},
			"redirect_uri":  {redirectURI},
			"code_verifier": {verifierCookie.Value},
		}
		req, err := http.NewRequest(http.MethodPost, issuer+"/token", strings.NewReader(form.Encode()))
		if err != nil {
			writeConfidentialPage(w, http.StatusInternalServerError, "Unable to request tokens", "", "")
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(oidc.DevRPConfidentialClientID, oidc.DevRPConfidentialSecret)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			writeConfidentialPage(w, http.StatusBadGateway, "Token request failed: "+err.Error(), "", "")
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			writeConfidentialPage(w, http.StatusBadGateway, "Token endpoint: "+string(body), "", "")
			return
		}

		var tokens map[string]any
		if err := json.Unmarshal(body, &tokens); err != nil {
			writeConfidentialPage(w, http.StatusBadGateway, "Invalid token response", "", "")
			return
		}
		idToken, _ := tokens["id_token"].(string)
		accessToken, _ := tokens["access_token"].(string)
		if idToken != "" {
			setRPCookie(w, cookieIDToken, idToken, 3600)
		}

		userinfo := fetchUserInfo(client, issuer, accessToken)
		writeConfidentialPage(w, http.StatusOK, "", userinfo, prettyJWT(idToken))
	}
}

func confidentialLogout(issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var idToken string
		if c, err := r.Cookie(cookieIDToken); err == nil {
			idToken = c.Value
		}
		clearRPCookie(w, cookieIDToken)
		clearRPCookie(w, cookieState)
		clearRPCookie(w, cookieVerifier)
		clearRPCookie(w, cookieNonce)

		q := url.Values{
			"post_logout_redirect_uri": {requestOrigin(r) + "/oidc-rp"},
			"client_id":                {oidc.DevRPConfidentialClientID},
		}
		if idToken != "" {
			q.Set("id_token_hint", idToken)
		}
		http.Redirect(w, r, issuer+"/end_session?"+q.Encode(), http.StatusFound)
	}
}

func fetchUserInfo(client *http.Client, issuer, accessToken string) string {
	if accessToken == "" {
		return "(no access token)"
	}
	req, err := http.NewRequest(http.MethodGet, issuer+"/userinfo", nil)
	if err != nil {
		return err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var v any
	if json.Unmarshal(b, &v) == nil {
		out, err := json.MarshalIndent(v, "", "  ")
		if err == nil {
			return string(out)
		}
	}
	return string(b)
}

func prettyJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return token
	}
	payload := parts[1]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return token
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(raw)
	}
	return string(out)
}

func writeConfidentialPage(w http.ResponseWriter, status int, errMsg, userinfo, idToken string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	msg := ""
	if errMsg != "" {
		msg = `<p class="message error" role="alert">` + html.EscapeString(errMsg) + `</p>`
	} else {
		msg = `<p class="message success">Signed in with the confidential client. Tokens were fetched by this server, not the browser.</p>`
	}
	userBlock := ""
	idBlock := ""
	logout := `<p><a href="/oidc-rp">Back</a></p>`
	if errMsg == "" {
		userBlock = `<h2>UserInfo</h2><pre>` + html.EscapeString(userinfo) + `</pre>`
		idBlock = `<h2>ID token</h2><pre>` + html.EscapeString(idToken) + `</pre>`
		logout = `<p><a class="button" href="/oidc-rp/confidential/logout">Sign out</a></p><p><a href="/oidc-rp">Back</a></p>`
	}
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>OIDC confidential callback</title><link rel="stylesheet" href="/oidc-rp.css"></head><body><main><h1>Confidential callback</h1><p class="hint">Client <code>oidc-rp-confidential</code> · <code>POST /oidc-idp/token</code> used HTTP Basic.</p>%s%s%s%s</main></body></html>`, msg, userBlock, idBlock, logout)
}

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:5000"
	}
	return scheme + "://" + host
}

func setRPCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/oidc-rp",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearRPCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/oidc-rp",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
	})
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
