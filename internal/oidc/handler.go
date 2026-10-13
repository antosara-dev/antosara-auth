package oidc

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/antosara-dev/antosara-auth/pkg"
	"github.com/go-chi/chi/v5"
)

// Handler is the OIDC Identity Provider mounted at /oidc-idp.
type Handler struct {
	users    pkg.UserRepository
	clients  ClientRepository
	stores   Stores
	sessions SessionManager
	signer   *tokenSigner
}

// Deps wires OIDC dependencies. SessionManager is typically *internal.AuthHandler.
type Deps struct {
	Users    pkg.UserRepository
	Clients  ClientRepository
	Stores   Stores
	Sessions SessionManager
}

// NewHandler constructs an OIDC IdP handler.
func NewHandler(deps Deps) (*Handler, error) {
	if deps.Users == nil {
		return nil, fmt.Errorf("oidc: user repository is required")
	}
	if deps.Clients == nil {
		return nil, fmt.Errorf("oidc: client repository is required")
	}
	if deps.Stores.Codes == nil || deps.Stores.Refresh == nil || deps.Stores.Consents == nil {
		return nil, fmt.Errorf("oidc: stores are required")
	}
	if deps.Sessions == nil {
		return nil, fmt.Errorf("oidc: session manager is required")
	}
	signer, err := newTokenSignerFromEnv()
	if err != nil {
		return nil, err
	}
	return &Handler{
		users:    deps.Users,
		clients:  deps.Clients,
		stores:   deps.Stores,
		sessions: deps.Sessions,
		signer:   signer,
	}, nil
}

// Mount registers OIDC routes on r, which should already be scoped to /oidc-idp.
// rateLimit is applied to protocol endpoints, not static assets or discovery.
func (h *Handler) Mount(r chi.Router, rateLimit func(http.Handler) http.Handler) {
	r.Get("/.well-known/openid-configuration", h.Discovery)
	r.Get("/login.css", h.serveLoginCSS)
	r.Get("/login.js", h.serveLoginJS)
	r.Get("/consent.css", h.serveConsentCSS)
	r.Get("/consent.js", h.serveConsentJS)

	limited := r
	if rateLimit != nil {
		limited = r.With(rateLimit)
	}

	limited.Get("/authorize", h.Authorize)
	limited.Post("/authorize", h.Authorize)
	limited.Post("/token", h.Token)
	limited.Get("/userinfo", h.UserInfo)
	limited.Post("/userinfo", h.UserInfo)
	limited.Get("/end_session", h.EndSession)
	limited.Post("/end_session", h.EndSession)

	r.Get("/login", h.LoginPage)
	limited.Post("/login", h.LoginSubmit)
	r.Get("/consent", h.ConsentPage)
	limited.Post("/consent", h.ConsentSubmit)
	r.Get("/logout", h.LogoutPage)
}

func requestParams(r *http.Request) (map[string]string, error) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
	}
	out := make(map[string]string)
	add := func(v string, src string) {
		if src == "" {
			return
		}
		out[v] = src
	}
	q := r.URL.Query()
	for k := range q {
		add(k, strings.TrimSpace(q.Get(k)))
	}
	if r.Method == http.MethodPost {
		for k := range r.Form {
			if _, exists := out[k]; !exists || r.Form.Get(k) != "" {
				add(k, strings.TrimSpace(r.Form.Get(k)))
			}
		}
	}
	return out, nil
}
