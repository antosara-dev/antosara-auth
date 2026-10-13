package oidc

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"
)

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	client, err := h.authenticateClient(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}

	grant := r.Form.Get("grant_type")
	switch grant {
	case GrantAuthorizationCode:
		h.tokenAuthorizationCode(w, r, client)
	case GrantRefreshToken:
		h.tokenRefresh(w, r, client)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant_type")
	}
}

func (h *Handler) authenticateClient(r *http.Request) (*Client, error) {
	id, secret, hasBasic := basicClientAuth(r)
	if !hasBasic {
		id = strings.TrimSpace(r.Form.Get("client_id"))
		secret = r.Form.Get("client_secret")
	}
	if id == "" {
		return nil, ErrInvalidClient
	}
	client, err := h.clients.GetByClientID(r.Context(), id)
	if err != nil {
		return nil, ErrInvalidClient
	}

	switch client.TokenEndpointAuthMethod {
	case AuthMethodNone:
		if !client.Public {
			return nil, ErrInvalidClient
		}
		if hasBasic || secret != "" {
			return nil, ErrInvalidClient
		}
		return client, nil
	case AuthMethodBasic:
		if !hasBasic {
			return nil, ErrInvalidClient
		}
		if err := client.checkSecret(secret); err != nil {
			return nil, err
		}
		return client, nil
	case AuthMethodPost:
		if hasBasic {
			return nil, ErrInvalidClient
		}
		if err := client.checkSecret(secret); err != nil {
			return nil, err
		}
		return client, nil
	default:
		return nil, ErrInvalidClient
	}
}

func basicClientAuth(r *http.Request) (id, secret string, ok bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(h), "basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[6:]))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (h *Handler) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request, client *Client) {
	if !client.AllowsGrant(GrantAuthorizationCode) {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client cannot use authorization_code")
		return
	}
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	verifier := r.Form.Get("code_verifier")
	if code == "" || redirectURI == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "code and redirect_uri are required")
		return
	}

	ac, err := h.stores.Codes.Consume(r.Context(), sha256Raw(code))
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")
		return
	}
	if ac.ClientID != client.ClientID || ac.RedirectURI != redirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Code does not match client or redirect_uri")
		return
	}
	if !verifyPKCE(verifier, ac.CodeChallenge) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	user, err := h.users.GetUserByEmail(r.Context(), ac.Sub)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "User no longer available")
		return
	}

	withRefresh := hasScope(splitScopes(ac.Scope), "offline_access") && client.AllowsGrant(GrantRefreshToken)
	minted, rec, err := h.mintTokens(mintInput{
		Sub:         ac.Sub,
		ClientID:    client.ClientID,
		Scope:       ac.Scope,
		Nonce:       ac.Nonce,
		AuthTime:    ac.AuthTime,
		Email:       user.Email,
		Alias:       user.Alias,
		Verified:    user.Verified,
		SessionJTI:  ac.SessionJTI,
		WithRefresh: withRefresh,
	})
	if err != nil {
		log.Printf("oidc: mint tokens: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to issue tokens")
		return
	}
	if minted.RefreshToken != "" {
		if err := h.stores.Refresh.Put(r.Context(), sha256Raw(minted.RefreshToken), rec); err != nil {
			log.Printf("oidc: store refresh token: %v", err)
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to issue tokens")
			return
		}
	}
	h.writeTokenResponse(w, minted)
}

func (h *Handler) tokenRefresh(w http.ResponseWriter, r *http.Request, client *Client) {
	if !client.AllowsGrant(GrantRefreshToken) {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client cannot use refresh_token")
		return
	}
	raw := r.Form.Get("refresh_token")
	if raw == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	rec, err := h.stores.Refresh.Consume(r.Context(), sha256Raw(raw))
	if errors.Is(err, ErrReuseDetected) {
		if rec != nil {
			_ = h.stores.Refresh.RevokeFamily(r.Context(), rec.FamilyID)
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token reuse detected")
		return
	}
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
		return
	}
	if rec.ClientID != client.ClientID {
		_ = h.stores.Refresh.RevokeFamily(r.Context(), rec.FamilyID)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token does not belong to client")
		return
	}

	user, err := h.users.GetUserByEmail(r.Context(), rec.Sub)
	if err != nil {
		_ = h.stores.Refresh.RevokeFamily(r.Context(), rec.FamilyID)
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "User no longer available")
		return
	}

	minted, next, err := h.mintTokens(mintInput{
		Sub:         rec.Sub,
		ClientID:    client.ClientID,
		Scope:       rec.Scope,
		AuthTime:    rec.AuthTime,
		Email:       user.Email,
		Alias:       user.Alias,
		Verified:    user.Verified,
		FamilyID:    rec.FamilyID,
		SessionJTI:  rec.SessionJTI,
		WithRefresh: true,
	})
	if err != nil {
		log.Printf("oidc: mint refresh tokens: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to issue tokens")
		return
	}
	if minted.RefreshToken == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "offline_access was not granted")
		return
	}
	next.FamilyID = rec.FamilyID
	if err := h.stores.Refresh.Put(r.Context(), sha256Raw(minted.RefreshToken), next); err != nil {
		log.Printf("oidc: rotate refresh token: %v", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Unable to issue tokens")
		return
	}
	h.writeTokenResponse(w, minted)
}

func (h *Handler) writeTokenResponse(w http.ResponseWriter, minted mintedTokens) {
	body := map[string]any{
		"access_token": minted.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   minted.ExpiresIn,
		"id_token":     minted.IDToken,
		"scope":        minted.Scope,
	}
	if minted.RefreshToken != "" {
		body["refresh_token"] = minted.RefreshToken
	}
	writeJSON(w, http.StatusOK, body)
}
