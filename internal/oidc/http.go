package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
)

var (
	ErrInvalidClient = errors.New("invalid_client")
	ErrNotFound      = errors.New("not found")
	ErrReuseDetected = errors.New("refresh token reuse")
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func writeHTMLError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Error</title></head><body><h1>Request cannot be completed</h1><p>%s</p></body></html>`, html.EscapeString(msg))
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, errCode, desc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "Invalid redirect_uri")
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func redirectCode(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "Invalid redirect_uri")
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
