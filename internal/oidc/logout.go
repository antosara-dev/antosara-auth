package oidc

import (
	"log"
	"net/http"
	"net/url"
)

func (h *Handler) EndSession(w http.ResponseWriter, r *http.Request) {
	params, err := requestParams(r)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	idTokenHint := params["id_token_hint"]
	postLogout := params["post_logout_redirect_uri"]
	state := params["state"]
	clientID := params["client_id"]

	var hintSub, hintClient string
	if idTokenHint != "" {
		if tok, err := h.signer.parse(idTokenHint); err == nil && tok.Issuer() == issuer() {
			hintSub = tok.Subject()
			if aud := tok.Audience(); len(aud) > 0 {
				hintClient = aud[0]
			}
		}
	}
	if clientID == "" {
		clientID = hintClient
	}

	email, _, loggedIn := h.sessions.CurrentUser(r)
	if hintSub != "" {
		if err := h.stores.Refresh.RevokeBySub(r.Context(), hintSub); err != nil {
			log.Printf("oidc: revoke refresh on logout: %v", err)
		}
	} else if loggedIn {
		if err := h.stores.Refresh.RevokeBySub(r.Context(), email); err != nil {
			log.Printf("oidc: revoke refresh on logout: %v", err)
		}
	}

	if err := h.sessions.Destroy(w, r); err != nil {
		log.Printf("oidc: destroy session: %v", err)
	}
	h.clearPending(w)

	if postLogout != "" {
		if clientID == "" {
			writeHTMLError(w, http.StatusBadRequest, "post_logout_redirect_uri requires client_id or id_token_hint")
			return
		}
		client, err := h.clients.GetByClientID(r.Context(), clientID)
		if err != nil || !client.AllowsPostLogoutRedirect(postLogout) {
			writeHTMLError(w, http.StatusBadRequest, "Invalid post_logout_redirect_uri")
			return
		}
		u, err := url.Parse(postLogout)
		if err != nil {
			writeHTMLError(w, http.StatusBadRequest, "Invalid post_logout_redirect_uri")
			return
		}
		if state != "" {
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
		}
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}

	renderLogout(w)
}

func (h *Handler) LogoutPage(w http.ResponseWriter, r *http.Request) {
	renderLogout(w)
}
