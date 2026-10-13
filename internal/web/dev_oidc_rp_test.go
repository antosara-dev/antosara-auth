package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

func TestRegisterDevOIDCRelyingParty(t *testing.T) {
	t.Setenv("ENABLE_OIDC_RP", "true")
	t.Setenv("HOST_NAME", "localhost")
	t.Setenv("OIDC_ISSUER", "http://localhost:5000/oidc-idp")

	r := chi.NewRouter()
	RegisterDevOIDCRelyingParty(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc-rp", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "http://localhost:5000/oidc-idp")
	require.Contains(t, rec.Body.String(), "oidc-rp-confidential")

	css := httptest.NewRecorder()
	r.ServeHTTP(css, httptest.NewRequest(http.MethodGet, "/oidc-rp.css", nil))
	require.Equal(t, http.StatusOK, css.Code)

	js := httptest.NewRecorder()
	r.ServeHTTP(js, httptest.NewRequest(http.MethodGet, "/oidc-rp.js", nil))
	require.Equal(t, http.StatusOK, js.Code)

	start := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oidc-rp/confidential", nil)
	req.Host = "localhost:5000"
	r.ServeHTTP(start, req)
	require.Equal(t, http.StatusFound, start.Code)
	loc := start.Header().Get("Location")
	require.Contains(t, loc, "client_id=oidc-rp-confidential")
	require.Contains(t, loc, url.QueryEscape("http://localhost:5000/oidc-rp/callback"))
	require.Contains(t, loc, "code_challenge_method=S256")
	require.NotEmpty(t, start.Result().Cookies())
}

func TestRegisterDevOIDCRelyingPartyDisabledByDefault(t *testing.T) {
	t.Setenv("ENABLE_OIDC_RP", "")
	t.Setenv("HOST_NAME", "localhost")
	t.Setenv("OIDC_ISSUER", "http://localhost:5000/oidc-idp")

	r := chi.NewRouter()
	RegisterDevOIDCRelyingParty(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc-rp", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
}
