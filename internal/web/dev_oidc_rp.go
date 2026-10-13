package web

import (
	_ "embed"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed oidc-rp.html
var oidcRPHTML []byte

//go:embed oidc-rp.js
var oidcRPJS []byte

//go:embed oidc-rp.css
var oidcRPCSS []byte

// RegisterDevOIDCRelyingParty serves an OIDC test app at /oidc-rp when ENABLE_OIDC_RP is set.
func RegisterDevOIDCRelyingParty(r chi.Router) {
	if !devOIDCRPEnabled() {
		return
	}

	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("OIDC_ISSUER")), "/")
	if issuer == "" {
		host := strings.TrimSpace(os.Getenv("HOST_NAME"))
		if host == "" {
			host = "localhost"
		}
		port := strings.TrimSpace(os.Getenv("PORT"))
		if port == "" {
			port = "5000"
		}
		issuer = "http://" + host
		if port != "80" {
			issuer += ":" + port
		}
		issuer += "/oidc-idp"
	}

	r.Get("/oidc-rp", func(w http.ResponseWriter, _ *http.Request) {
		page := strings.ReplaceAll(string(oidcRPHTML), "{{ISSUER}}", issuer)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})
	r.Get("/oidc-rp.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write(oidcRPJS)
	})
	r.Get("/oidc-rp.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(oidcRPCSS)
	})
	registerConfidentialRP(r, issuer)

	log.Printf("Dev OIDC relying party enabled at /oidc-rp (issuer %s; public %s, confidential %s)", issuer, "oidc-rp", "oidc-rp-confidential")
}

func devOIDCRPEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ENABLE_OIDC_RP"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
