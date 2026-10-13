package oidc

import (
	_ "embed"
	"html"
	"net/http"
	"strings"
)

//go:embed pages/login.html
var loginHTML string

//go:embed pages/login.css
var loginCSS []byte

//go:embed pages/login.js
var loginJS []byte

//go:embed pages/consent.html
var consentHTML string

//go:embed pages/consent.js
var consentJS []byte

//go:embed pages/logout.html
var logoutHTML string

func (h *Handler) serveLoginCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(loginCSS)
}

func (h *Handler) serveLoginJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(loginJS)
}

func (h *Handler) serveConsentCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(loginCSS)
}

func (h *Handler) serveConsentJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(consentJS)
}

func renderLogin(w http.ResponseWriter, clientID, csrf, email, errMsg string) {
	page := loginHTML
	page = strings.ReplaceAll(page, "{{CLIENT_ID}}", html.EscapeString(clientID))
	page = strings.ReplaceAll(page, "{{CSRF}}", html.EscapeString(csrf))
	page = strings.ReplaceAll(page, "{{EMAIL}}", html.EscapeString(email))
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="message error" role="alert">` + html.EscapeString(errMsg) + `</p>`
	}
	page = strings.ReplaceAll(page, "{{ERROR}}", errBlock)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

func renderConsent(w http.ResponseWriter, clientID, csrf string, scopes []string, errMsg string) {
	page := consentHTML
	page = strings.ReplaceAll(page, "{{CLIENT_ID}}", html.EscapeString(clientID))
	page = strings.ReplaceAll(page, "{{CSRF}}", html.EscapeString(csrf))
	var items []string
	for _, s := range scopes {
		items = append(items, "<li>"+html.EscapeString(s)+"</li>")
	}
	page = strings.ReplaceAll(page, "{{SCOPES}}", strings.Join(items, ""))
	errBlock := ""
	if errMsg != "" {
		errBlock = `<p class="message error" role="alert">` + html.EscapeString(errMsg) + `</p>`
	}
	page = strings.ReplaceAll(page, "{{ERROR}}", errBlock)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

func renderLogout(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(logoutHTML))
}
