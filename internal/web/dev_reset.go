package web

import (
	_ "embed"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed reset-password.html
var resetPasswordHTML []byte

//go:embed reset-password.js
var resetPasswordJS []byte

//go:embed reset-password.css
var resetPasswordCSS []byte

// RegisterDevPasswordResetPage serves the embedded reset-password page when
// PASSWORD_RESET_URL points at localhost. Intended for local development only.
func RegisterDevPasswordResetPage(r chi.Router) {
	resetURL := strings.TrimSpace(os.Getenv("PASSWORD_RESET_URL"))
	if resetURL == "" {
		return
	}

	parsed, err := url.Parse(resetURL)
	if err != nil {
		log.Printf("PASSWORD_RESET_URL is invalid, skipping dev reset page: %v", err)
		return
	}

	if !isLocalhost(parsed.Hostname()) {
		return
	}

	pagePath := parsed.Path
	if pagePath == "" {
		pagePath = "/"
	}

	assetBase := devResetAssetBase(pagePath)

	r.Get(pagePath, func(w http.ResponseWriter, r *http.Request) {
		token := html.EscapeString(r.URL.Query().Get("token"))
		page := strings.ReplaceAll(string(resetPasswordHTML), "{{TOKEN}}", token)
		page = strings.ReplaceAll(page, "{{ASSET_BASE}}", assetBase)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})
	r.Get(assetBase+"/reset-password.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Write(resetPasswordJS)
	})
	r.Get(assetBase+"/reset-password.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(resetPasswordCSS)
	})

	log.Printf("Dev password reset page enabled at %s", pagePath)
}

func isLocalhost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func devResetAssetBase(pagePath string) string {
	if pagePath == "/" {
		return ""
	}
	return strings.TrimSuffix(path.Dir(pagePath), "/")
}
