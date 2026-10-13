package oidc

import (
	"log"
	"net/http"
	"strings"
	"time"
)

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	params, err := requestParams(r)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	pending, _ := h.getPending(r)
	if params["client_id"] == "" && pending != nil {
		h.continuePending(w, r, pending)
		return
	}

	p, client, ok := h.validateAuthorizeRequest(w, r, params)
	if !ok {
		return
	}
	if err := h.setPending(w, p); err != nil {
		log.Printf("oidc: persist pending request: %v", err)
		writeHTMLError(w, http.StatusInternalServerError, "Unable to process request")
		return
	}
	_ = client
	h.continuePending(w, r, &p)
}

func (h *Handler) validateAuthorizeRequest(w http.ResponseWriter, r *http.Request, params map[string]string) (pendingRequest, *Client, bool) {
	clientID := params["client_id"]
	redirectURI := params["redirect_uri"]
	state := params["state"]

	if clientID == "" {
		writeHTMLError(w, http.StatusBadRequest, "Missing client_id")
		return pendingRequest{}, nil, false
	}
	client, err := h.clients.GetByClientID(r.Context(), clientID)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "Unknown client_id")
		return pendingRequest{}, nil, false
	}
	if redirectURI == "" || !client.AllowsRedirect(redirectURI) {
		writeHTMLError(w, http.StatusBadRequest, "Invalid redirect_uri")
		return pendingRequest{}, nil, false
	}

	fail := func(code, desc string) (pendingRequest, *Client, bool) {
		redirectOAuthError(w, r, redirectURI, code, desc, state)
		return pendingRequest{}, nil, false
	}

	if params["response_type"] != "code" {
		return fail("unsupported_response_type", "Only response_type=code is supported")
	}
	if !client.AllowsGrant(GrantAuthorizationCode) {
		return fail("unauthorized_client", "Client is not allowed to use authorization_code")
	}

	scopes, err := filterSupportedScopes(splitScopes(params["scope"]))
	if err != nil {
		return fail("invalid_scope", err.Error())
	}

	if params["code_challenge"] == "" || params["code_challenge_method"] != "S256" {
		return fail("invalid_request", "PKCE S256 is required")
	}
	if len(params["code_challenge"]) < 43 || len(params["code_challenge"]) > 128 {
		return fail("invalid_request", "Invalid code_challenge")
	}

	promptLogin, _, _, err := parsePrompt(params["prompt"])
	if err != nil {
		return fail("invalid_request", err.Error())
	}

	p := pendingRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               params["nonce"],
		Scope:               joinScopes(scopes),
		CodeChallenge:       params["code_challenge"],
		CodeChallengeMethod: "S256",
		Prompt:              params["prompt"],
		ForceLogin:          promptLogin,
	}
	return p, client, true
}

func (h *Handler) continuePending(w http.ResponseWriter, r *http.Request, p *pendingRequest) {
	_, promptConsent, promptNone, err := parsePrompt(p.Prompt)
	if err != nil {
		redirectOAuthError(w, r, p.RedirectURI, "invalid_request", err.Error(), p.State)
		return
	}

	email, jti, loggedIn := h.sessions.CurrentUser(r)
	if p.ForceLogin {
		loggedIn = false
	}

	if promptNone {
		if !loggedIn {
			redirectOAuthError(w, r, p.RedirectURI, "login_required", "Login required", p.State)
			return
		}
		if promptConsent || !h.hasConsent(r, email, p.ClientID, splitScopes(p.Scope)) {
			redirectOAuthError(w, r, p.RedirectURI, "consent_required", "Consent required", p.State)
			return
		}
		h.issueCode(w, r, p, email, jti)
		return
	}

	if !loggedIn {
		http.Redirect(w, r, "/oidc-idp/login", http.StatusFound)
		return
	}

	if promptConsent || !h.hasConsent(r, email, p.ClientID, splitScopes(p.Scope)) {
		http.Redirect(w, r, "/oidc-idp/consent", http.StatusFound)
		return
	}

	h.issueCode(w, r, p, email, jti)
}

func (h *Handler) hasConsent(r *http.Request, sub, clientID string, requested []string) bool {
	c, err := h.stores.Consents.Get(r.Context(), sub, clientID)
	if err != nil {
		return false
	}
	return scopesGranted(splitScopes(c.Scope), requested)
}

func (h *Handler) issueCode(w http.ResponseWriter, r *http.Request, p *pendingRequest, sub, jti string) {
	code, err := randomToken(32)
	if err != nil {
		writeHTMLError(w, http.StatusInternalServerError, "Unable to issue authorization code")
		return
	}
	now := time.Now()
	ac := AuthCode{
		ClientID:      p.ClientID,
		RedirectURI:   p.RedirectURI,
		CodeChallenge: p.CodeChallenge,
		Nonce:         p.Nonce,
		Scope:         p.Scope,
		Sub:           sub,
		SessionJTI:    jti,
		AuthTime:      now,
		ExpiresAt:     now.Add(authCodeTTL()),
	}
	if err := h.stores.Codes.Put(r.Context(), sha256Raw(code), ac); err != nil {
		log.Printf("oidc: store auth code: %v", err)
		writeHTMLError(w, http.StatusInternalServerError, "Unable to issue authorization code")
		return
	}
	h.clearPending(w)
	redirectCode(w, r, p.RedirectURI, code, p.State)
}

func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	p, err := h.getPending(r)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "No authorization request in progress")
		return
	}
	renderLogin(w, p.ClientID, p.CSRF, "", "")
}

func (h *Handler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	p, err := h.getPending(r)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "No authorization request in progress")
		return
	}
	if err := r.ParseForm(); err != nil {
		renderLogin(w, p.ClientID, p.CSRF, "", "Invalid request")
		return
	}
	if strings.TrimSpace(r.Form.Get("csrf")) != p.CSRF {
		renderLogin(w, p.ClientID, p.CSRF, "", "Invalid request")
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.Form.Get("email")))
	password := r.Form.Get("password")
	user, err := h.sessions.Authenticate(r.Context(), email, password)
	if err != nil {
		msg := "Invalid credentials"
		if strings.Contains(strings.ToLower(err.Error()), "locked") {
			msg = err.Error()
		}
		renderLogin(w, p.ClientID, p.CSRF, email, msg)
		return
	}
	if err := h.sessions.Establish(w, r, user.Email); err != nil {
		log.Printf("oidc: establish session: %v", err)
		renderLogin(w, p.ClientID, p.CSRF, email, "Unable to sign in")
		return
	}
	p.ForceLogin = false
	if err := h.setPending(w, *p); err != nil {
		log.Printf("oidc: update pending after login: %v", err)
	}
	http.Redirect(w, r, "/oidc-idp/authorize", http.StatusFound)
}

func (h *Handler) ConsentPage(w http.ResponseWriter, r *http.Request) {
	p, err := h.getPending(r)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "No authorization request in progress")
		return
	}
	if _, _, ok := h.sessions.CurrentUser(r); !ok {
		http.Redirect(w, r, "/oidc-idp/login", http.StatusFound)
		return
	}
	renderConsent(w, p.ClientID, p.CSRF, splitScopes(p.Scope), "")
}

func (h *Handler) ConsentSubmit(w http.ResponseWriter, r *http.Request) {
	p, err := h.getPending(r)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "No authorization request in progress")
		return
	}
	email, jti, ok := h.sessions.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, "/oidc-idp/login", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderConsent(w, p.ClientID, p.CSRF, splitScopes(p.Scope), "Invalid request")
		return
	}
	if strings.TrimSpace(r.Form.Get("csrf")) != p.CSRF {
		renderConsent(w, p.ClientID, p.CSRF, splitScopes(p.Scope), "Invalid request")
		return
	}
	if r.Form.Get("decision") == "deny" {
		h.clearPending(w)
		redirectOAuthError(w, r, p.RedirectURI, "access_denied", "The user denied the request", p.State)
		return
	}
	if r.Form.Get("decision") != "allow" {
		renderConsent(w, p.ClientID, p.CSRF, splitScopes(p.Scope), "Choose Allow or Deny")
		return
	}
	if err := h.stores.Consents.Put(r.Context(), Consent{
		Sub:      email,
		ClientID: p.ClientID,
		Scope:    p.Scope,
	}); err != nil {
		log.Printf("oidc: store consent: %v", err)
		renderConsent(w, p.ClientID, p.CSRF, splitScopes(p.Scope), "Unable to save consent")
		return
	}
	h.issueCode(w, r, p, email, jti)
}
