package oidc

import (
	"net/http"
	"os"
	"time"
)

const pendingCookieName = "oidc_ar"

// pendingRequest is the in-progress authorization request, stored as a signed cookie.
type pendingRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	CSRF                string
	ForceLogin          bool
	ExpiresAt           int64
}

func (h *Handler) setPending(w http.ResponseWriter, p pendingRequest) error {
	if p.CSRF == "" {
		csrf, err := randomToken(16)
		if err != nil {
			return err
		}
		p.CSRF = csrf
	}
	if p.ExpiresAt == 0 {
		p.ExpiresAt = time.Now().Add(pendingTTL()).Unix()
	}
	token, err := h.signer.signClaims(map[string]any{
		"iss":                   issuer(),
		"aud":                   issuer(),
		"exp":                   p.ExpiresAt,
		"iat":                   time.Now().Unix(),
		"token_use":             "oidc_pending",
		"client_id":             p.ClientID,
		"redirect_uri":          p.RedirectURI,
		"state":                 p.State,
		"nonce":                 p.Nonce,
		"scope":                 p.Scope,
		"code_challenge":        p.CodeChallenge,
		"code_challenge_method": p.CodeChallengeMethod,
		"prompt":                p.Prompt,
		"csrf":                  p.CSRF,
		"force_login":           p.ForceLogin,
	})
	if err != nil {
		return err
	}
	http.SetCookie(w, pendingCookie(token, int(pendingTTL().Seconds())))
	return nil
}

func (h *Handler) getPending(r *http.Request) (*pendingRequest, error) {
	c, err := r.Cookie(pendingCookieName)
	if err != nil || c.Value == "" {
		return nil, ErrNotFound
	}
	tok, err := h.signer.parse(c.Value)
	if err != nil {
		return nil, err
	}
	use, _ := tok.Get("token_use")
	if use != "oidc_pending" {
		return nil, ErrNotFound
	}
	str := func(key string) string {
		v, _ := tok.Get(key)
		s, _ := v.(string)
		return s
	}
	p := &pendingRequest{
		ClientID:            str("client_id"),
		RedirectURI:         str("redirect_uri"),
		State:               str("state"),
		Nonce:               str("nonce"),
		Scope:               str("scope"),
		CodeChallenge:       str("code_challenge"),
		CodeChallengeMethod: str("code_challenge_method"),
		Prompt:              str("prompt"),
		CSRF:                str("csrf"),
	}
	if v, ok := tok.Get("force_login"); ok {
		switch t := v.(type) {
		case bool:
			p.ForceLogin = t
		case string:
			p.ForceLogin = t == "true"
		}
	}
	p.ExpiresAt = tok.Expiration().Unix()
	return p, nil
}

func (h *Handler) clearPending(w http.ResponseWriter) {
	http.SetCookie(w, pendingCookie("", -1))
}

func pendingCookie(value string, maxAge int) *http.Cookie {
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	c := &http.Cookie{
		Name:     pendingCookieName,
		Value:    value,
		Path:     "/oidc-idp",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if cookieDomain != "" {
		c.Domain = cookieDomain
	}
	if maxAge < 0 {
		c.Expires = time.Unix(0, 0)
	}
	return c
}
