package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/antosara-dev/antosara-auth/pkg"
	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type fakeUserRepo struct {
	users map[string]*pkg.User
}

func (f *fakeUserRepo) GetUserByEmail(_ context.Context, email string) (*pkg.User, error) {
	u, ok := f.users[email]
	if !ok {
		return nil, pkg.ErrUserNotFound
	}
	copy := *u
	return &copy, nil
}
func (f *fakeUserRepo) CreateUser(context.Context, *pkg.User) error { return nil }
func (f *fakeUserRepo) UpdateUser(_ context.Context, user *pkg.User) error {
	copy := *user
	f.users[user.Email] = &copy
	return nil
}
func (f *fakeUserRepo) DeleteUser(context.Context, string) error { return nil }
func (f *fakeUserRepo) GetUserByResetToken(context.Context, string) (*pkg.User, error) {
	return nil, pkg.ErrUserNotFound
}

type fakeSession struct {
	repo *fakeUserRepo
}

func (f *fakeSession) CurrentUser(r *http.Request) (string, string, bool) {
	c, err := r.Cookie("oidc_test_session")
	if err != nil || c.Value == "" {
		return "", "", false
	}
	return c.Value, "session-jti-1", true
}

func (f *fakeSession) Establish(w http.ResponseWriter, _ *http.Request, email string) error {
	http.SetCookie(w, &http.Cookie{Name: "oidc_test_session", Value: email, Path: "/", MaxAge: 3600})
	return nil
}

func (f *fakeSession) Destroy(w http.ResponseWriter, _ *http.Request) error {
	http.SetCookie(w, &http.Cookie{Name: "oidc_test_session", Path: "/", MaxAge: -1})
	return nil
}

func (f *fakeSession) Authenticate(ctx context.Context, email, password string) (*pkg.User, error) {
	user, err := f.repo.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return nil, pkg.ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		return nil, pkg.ErrInvalidCredentials
	}
	if !user.Verified {
		return nil, pkg.ErrInvalidCredentials
	}
	return user, nil
}

type cookieJar struct {
	cookies map[string]*http.Cookie
}

func newJar() *cookieJar {
	return &cookieJar{cookies: map[string]*http.Cookie{}}
}

func (j *cookieJar) take(resp *http.Response) {
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(j.cookies, c.Name)
			continue
		}
		cp := *c
		j.cookies[c.Name] = &cp
	}
}

func (j *cookieJar) apply(req *http.Request) {
	for _, c := range j.cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
}

func testRSAEnv(t *testing.T) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	t.Setenv("JWT_PRIVATE_KEY", string(priv))
	t.Setenv("JWT_PUBLIC_KEY", string(pub))
	t.Setenv("JWT_ISSUER", "https://auth.example.test")
	t.Setenv("JWT_TYPE", "access")
	t.Setenv("OIDC_ISSUER", "https://auth.example.test/oidc-idp")
	t.Setenv("HOST_NAME", "auth.example.test")
}

func pkce(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func setupOIDC(t *testing.T) (*Handler, http.Handler, *fakeUserRepo, *Client) {
	t.Helper()
	testRSAEnv(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("Password1!"), bcrypt.MinCost)
	require.NoError(t, err)
	repo := &fakeUserRepo{users: map[string]*pkg.User{
		"user@example.com": {
			Email:    "user@example.com",
			Alias:    "User",
			Password: string(hash),
			Verified: true,
		},
	}}

	conf, err := NewStaticClientRepository([]*Client{{
		ClientID:                "confidential",
		ClientSecretHash:        mustBcrypt(t, "s3cret"),
		RedirectURIs:            []string{"https://rp.example.test/callback"},
		PostLogoutRedirectURIs:  []string{"https://rp.example.test/logout"},
		TokenEndpointAuthMethod: AuthMethodBasic,
		GrantTypes:              []string{GrantAuthorizationCode, GrantRefreshToken},
	}, {
		ClientID:                "public-app",
		Public:                  true,
		RedirectURIs:            []string{"https://spa.example.test/callback"},
		TokenEndpointAuthMethod: AuthMethodNone,
		GrantTypes:              []string{GrantAuthorizationCode, GrantRefreshToken},
	}})
	require.NoError(t, err)

	h, err := NewHandler(Deps{
		Users:    repo,
		Clients:  conf,
		Stores:   NewMemoryOIDCStores(),
		Sessions: &fakeSession{repo: repo},
	})
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Route("/oidc-idp", func(r chi.Router) {
		h.Mount(r, nil)
	})
	client, err := conf.GetByClientID(context.Background(), "confidential")
	require.NoError(t, err)
	return h, r, repo, client
}

func mustBcrypt(t *testing.T, secret string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	require.NoError(t, err)
	return string(hash)
}

func doReq(t *testing.T, h http.Handler, jar *cookieJar, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	contentType := ""
	if form != nil {
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}
	req := httptest.NewRequest(method, path, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if jar != nil {
		jar.apply(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if jar != nil {
		jar.take(resp)
	}
	return rec
}

func TestDiscovery(t *testing.T) {
	_, h, _, _ := setupOIDC(t)
	rec := doReq(t, h, nil, http.MethodGet, "/oidc-idp/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, rec.Code)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	require.Equal(t, "https://auth.example.test/oidc-idp", doc["issuer"])
	require.Equal(t, "https://auth.example.test/.well-known/jwks.json", doc["jwks_uri"])
	require.Equal(t, "https://auth.example.test/oidc-idp/authorize", doc["authorization_endpoint"])
	require.Equal(t, "https://auth.example.test/oidc-idp/token", doc["token_endpoint"])
	require.Equal(t, "https://auth.example.test/oidc-idp/userinfo", doc["userinfo_endpoint"])
	require.Equal(t, "https://auth.example.test/oidc-idp/end_session", doc["end_session_endpoint"])
	require.Equal(t, []any{"code"}, doc["response_types_supported"])
}

func TestAuthorizeRejectsUnknownRedirect(t *testing.T) {
	_, h, _, _ := setupOIDC(t)
	_, challenge := pkce(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"confidential"},
		"redirect_uri":          {"https://evil.example/callback"},
		"scope":                 {"openid"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := doReq(t, h, nil, http.MethodGet, "/oidc-idp/authorize?"+q.Encode(), nil)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.NotContains(t, rec.Header().Get("Location"), "code=")
}

func TestPromptNoneLoginRequired(t *testing.T) {
	_, h, _, _ := setupOIDC(t)
	_, challenge := pkce(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"confidential"},
		"redirect_uri":          {"https://rp.example.test/callback"},
		"scope":                 {"openid"},
		"state":                 {"xyz"},
		"prompt":                {"none"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := doReq(t, h, nil, http.MethodGet, "/oidc-idp/authorize?"+q.Encode(), nil)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https://rp.example.test/callback", loc.Scheme+"://"+loc.Host+loc.Path)
	require.Equal(t, "login_required", loc.Query().Get("error"))
	require.Equal(t, "xyz", loc.Query().Get("state"))
}

func TestAuthorizationCodePKCEFlow(t *testing.T) {
	_, handler, _, _ := setupOIDC(t)
	verifier, challenge := pkce(t)
	jar := newJar()

	authQ := url.Values{
		"response_type":         {"code"},
		"client_id":             {"confidential"},
		"redirect_uri":          {"https://rp.example.test/callback"},
		"scope":                 {"openid email profile offline_access"},
		"state":                 {"st"},
		"nonce":                 {"n-1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize?"+authQ.Encode(), nil)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/oidc-idp/login", rec.Header().Get("Location"))

	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/login", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	csrf := formValue(rec.Body.String(), "csrf")
	require.NotEmpty(t, csrf)

	rec = doReq(t, handler, jar, http.MethodPost, "/oidc-idp/login", url.Values{
		"csrf":     {csrf},
		"email":    {"user@example.com"},
		"password": {"Password1!"},
	})
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/oidc-idp/authorize", rec.Header().Get("Location"))

	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize", nil)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/oidc-idp/consent", rec.Header().Get("Location"))

	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/consent", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	csrf = formValue(rec.Body.String(), "csrf")
	require.NotEmpty(t, csrf)

	rec = doReq(t, handler, jar, http.MethodPost, "/oidc-idp/consent", url.Values{
		"csrf":     {csrf},
		"decision": {"allow"},
	})
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "st", loc.Query().Get("state"))
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)

	tokenRec := tokenRequest(t, handler, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {"https://rp.example.test/callback"},
		"code_verifier": {verifier},
	}, "confidential", "s3cret")
	require.Equal(t, http.StatusOK, tokenRec.Code, tokenRec.Body.String())

	var tokens map[string]any
	require.NoError(t, json.Unmarshal(tokenRec.Body.Bytes(), &tokens))
	access, _ := tokens["access_token"].(string)
	idToken, _ := tokens["id_token"].(string)
	refresh, _ := tokens["refresh_token"].(string)
	require.NotEmpty(t, access)
	require.NotEmpty(t, idToken)
	require.NotEmpty(t, refresh)

	parsedID, err := jwt.Parse([]byte(idToken), jwt.WithVerify(false), jwt.WithValidate(false))
	require.NoError(t, err)
	require.Equal(t, "https://auth.example.test/oidc-idp", parsedID.Issuer())
	require.Equal(t, []string{"confidential"}, parsedID.Audience())
	require.Equal(t, "user@example.com", parsedID.Subject())
	nonce, _ := parsedID.Get("nonce")
	require.Equal(t, "n-1", nonce)
	_, hasType := parsedID.Get("type")
	require.False(t, hasType)

	parsedAT, err := jwt.Parse([]byte(access), jwt.WithVerify(false), jwt.WithValidate(false))
	require.NoError(t, err)
	use, _ := parsedAT.Get("token_use")
	require.Equal(t, "access", use)
	_, hasType = parsedAT.Get("type")
	require.False(t, hasType)

	req := httptest.NewRequest(http.MethodGet, "/oidc-idp/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	ui := httptest.NewRecorder()
	handler.ServeHTTP(ui, req)
	require.Equal(t, http.StatusOK, ui.Code)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(ui.Body.Bytes(), &claims))
	require.Equal(t, "user@example.com", claims["sub"])
	require.Equal(t, "user@example.com", claims["email"])
	require.Equal(t, true, claims["email_verified"])
	require.Equal(t, "User", claims["name"])

	replay := tokenRequest(t, handler, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {"https://rp.example.test/callback"},
		"code_verifier": {verifier},
	}, "confidential", "s3cret")
	require.Equal(t, http.StatusBadRequest, replay.Code)
	require.Contains(t, replay.Body.String(), "invalid_grant")

	badVerifier := tokenRequest(t, handler, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {"not-the-code"},
		"redirect_uri":  {"https://rp.example.test/callback"},
		"code_verifier": {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}, "confidential", "s3cret")
	require.Equal(t, http.StatusBadRequest, badVerifier.Code)

	refreshRec := tokenRequest(t, handler, url.Values{
		"grant_type":    {GrantRefreshToken},
		"refresh_token": {refresh},
	}, "confidential", "s3cret")
	require.Equal(t, http.StatusOK, refreshRec.Code, refreshRec.Body.String())
	var rotated map[string]any
	require.NoError(t, json.Unmarshal(refreshRec.Body.Bytes(), &rotated))
	newRefresh, _ := rotated["refresh_token"].(string)
	require.NotEmpty(t, newRefresh)
	require.NotEqual(t, refresh, newRefresh)

	reuse := tokenRequest(t, handler, url.Values{
		"grant_type":    {GrantRefreshToken},
		"refresh_token": {refresh},
	}, "confidential", "s3cret")
	require.Equal(t, http.StatusBadRequest, reuse.Code)
	require.Contains(t, reuse.Body.String(), "invalid_grant")

	afterReuse := tokenRequest(t, handler, url.Values{
		"grant_type":    {GrantRefreshToken},
		"refresh_token": {newRefresh},
	}, "confidential", "s3cret")
	require.Equal(t, http.StatusBadRequest, afterReuse.Code)
}

func TestConsentPersistsAndPromptConsent(t *testing.T) {
	_, handler, _, _ := setupOIDC(t)
	_, challenge := pkce(t)
	jar := newJar()
	completeLoginAndConsent(t, handler, jar, challenge, "openid email")

	_, challenge2 := pkce(t)
	authQ := url.Values{
		"response_type":         {"code"},
		"client_id":             {"confidential"},
		"redirect_uri":          {"https://rp.example.test/callback"},
		"scope":                 {"openid email"},
		"state":                 {"again"},
		"code_challenge":        {challenge2},
		"code_challenge_method": {"S256"},
	}
	rec := doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize?"+authQ.Encode(), nil)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.NotEmpty(t, loc.Query().Get("code"))

	_, challenge3 := pkce(t)
	authQ.Set("prompt", "consent")
	authQ.Set("code_challenge", challenge3)
	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize?"+authQ.Encode(), nil)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/oidc-idp/consent", rec.Header().Get("Location"))
}

func TestPromptNoneWithSessionAndConsent(t *testing.T) {
	_, handler, _, _ := setupOIDC(t)
	_, challenge := pkce(t)
	jar := newJar()
	completeLoginAndConsent(t, handler, jar, challenge, "openid")

	_, challenge2 := pkce(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"confidential"},
		"redirect_uri":          {"https://rp.example.test/callback"},
		"scope":                 {"openid"},
		"prompt":                {"none"},
		"state":                 {"pnone"},
		"code_challenge":        {challenge2},
		"code_challenge_method": {"S256"},
	}
	rec := doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize?"+q.Encode(), nil)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.NotEmpty(t, loc.Query().Get("code"))
	require.Equal(t, "pnone", loc.Query().Get("state"))
}

func TestPromptLoginForcesReauthThenIssuesCode(t *testing.T) {
	_, handler, _, _ := setupOIDC(t)
	_, challenge := pkce(t)
	jar := newJar()
	completeLoginAndConsent(t, handler, jar, challenge, "openid")

	_, challenge2 := pkce(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"confidential"},
		"redirect_uri":          {"https://rp.example.test/callback"},
		"scope":                 {"openid"},
		"prompt":                {"login"},
		"state":                 {"reauth"},
		"code_challenge":        {challenge2},
		"code_challenge_method": {"S256"},
	}
	rec := doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize?"+q.Encode(), nil)
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/oidc-idp/login", rec.Header().Get("Location"))

	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/login", nil)
	csrf := formValue(rec.Body.String(), "csrf")
	rec = doReq(t, handler, jar, http.MethodPost, "/oidc-idp/login", url.Values{
		"csrf": {csrf}, "email": {"user@example.com"}, "password": {"Password1!"},
	})
	require.Equal(t, "/oidc-idp/authorize", rec.Header().Get("Location"))
	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize", nil)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.NotEmpty(t, loc.Query().Get("code"), rec.Header().Get("Location"))
	require.Equal(t, "reauth", loc.Query().Get("state"))
}

func TestEndSessionRedirect(t *testing.T) {
	_, handler, _, _ := setupOIDC(t)
	verifier, challenge := pkce(t)
	jar := newJar()
	code := completeLoginAndConsent(t, handler, jar, challenge, "openid")
	tokenRec := tokenRequest(t, handler, url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {"https://rp.example.test/callback"},
		"code_verifier": {verifier},
	}, "confidential", "s3cret")
	require.Equal(t, http.StatusOK, tokenRec.Code)
	var tokens map[string]any
	require.NoError(t, json.Unmarshal(tokenRec.Body.Bytes(), &tokens))
	idToken, _ := tokens["id_token"].(string)

	q := url.Values{
		"id_token_hint":            {idToken},
		"post_logout_redirect_uri": {"https://rp.example.test/logout"},
		"state":                    {"bye"},
	}
	rec := doReq(t, handler, jar, http.MethodGet, "/oidc-idp/end_session?"+q.Encode(), nil)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https://rp.example.test/logout", loc.Scheme+"://"+loc.Host+loc.Path)
	require.Equal(t, "bye", loc.Query().Get("state"))
	_, loggedIn := jar.cookies["oidc_test_session"]
	require.False(t, loggedIn)
}

func TestPublicClientPKCE(t *testing.T) {
	_, handler, _, _ := setupOIDC(t)
	verifier, challenge := pkce(t)
	jar := newJar()

	authQ := url.Values{
		"response_type":         {"code"},
		"client_id":             {"public-app"},
		"redirect_uri":          {"https://spa.example.test/callback"},
		"scope":                 {"openid"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize?"+authQ.Encode(), nil)
	require.Equal(t, "/oidc-idp/login", rec.Header().Get("Location"))
	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/login", nil)
	csrf := formValue(rec.Body.String(), "csrf")
	rec = doReq(t, handler, jar, http.MethodPost, "/oidc-idp/login", url.Values{
		"csrf": {csrf}, "email": {"user@example.com"}, "password": {"Password1!"},
	})
	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize", nil)
	require.Equal(t, "/oidc-idp/consent", rec.Header().Get("Location"))
	rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/consent", nil)
	csrf = formValue(rec.Body.String(), "csrf")
	rec = doReq(t, handler, jar, http.MethodPost, "/oidc-idp/consent", url.Values{"csrf": {csrf}, "decision": {"allow"}})
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")

	req := httptest.NewRequest(http.MethodPost, "/oidc-idp/token", strings.NewReader(url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {"https://spa.example.test/callback"},
		"client_id":     {"public-app"},
		"code_verifier": {verifier},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	handler.ServeHTTP(tokenRec, req)
	require.Equal(t, http.StatusOK, tokenRec.Code, tokenRec.Body.String())
}

func TestLoadClientsFromEnv(t *testing.T) {
	t.Setenv("OIDC_CLIENTS", `[{"client_id":"a","client_secret":"x","redirect_uris":["https://a.test/cb"]}]`)
	repo, err := LoadClientsFromEnv()
	require.NoError(t, err)
	c, err := repo.GetByClientID(context.Background(), "a")
	require.NoError(t, err)
	require.False(t, c.Public)
	require.True(t, c.AllowsRedirect("https://a.test/cb"))
	require.False(t, c.AllowsRedirect("https://a.test/cb/"))
}

func TestRegisterDevRPClient(t *testing.T) {
	t.Setenv("ENABLE_OIDC_RP", "true")
	repo, err := NewStaticClientRepository(nil)
	require.NoError(t, err)
	require.True(t, RegisterDevRPClient(repo, "5000"))
	c, err := repo.GetByClientID(context.Background(), DevRPClientID)
	require.NoError(t, err)
	require.True(t, c.Public)
	require.True(t, c.AllowsRedirect("http://localhost:5000/oidc-rp"))
	require.True(t, c.AllowsPostLogoutRedirect("http://127.0.0.1:5000/oidc-rp"))

	conf, err := repo.GetByClientID(context.Background(), DevRPConfidentialClientID)
	require.NoError(t, err)
	require.False(t, conf.Public)
	require.Equal(t, AuthMethodBasic, conf.TokenEndpointAuthMethod)
	require.True(t, conf.AllowsRedirect("http://localhost:5000/oidc-rp/callback"))
	require.True(t, conf.AllowsPostLogoutRedirect("http://localhost:5000/oidc-rp"))
	require.False(t, conf.AllowsRedirect("http://localhost:5000/oidc-rp"))
}

func TestRegisterDevRPClientDisabledByDefault(t *testing.T) {
	t.Setenv("ENABLE_OIDC_RP", "")
	repo, err := NewStaticClientRepository(nil)
	require.NoError(t, err)
	require.False(t, RegisterDevRPClient(repo, "5000"))
	_, err = repo.GetByClientID(context.Background(), DevRPClientID)
	require.ErrorIs(t, err, ErrInvalidClient)
}

func TestSQLStoresAuthCodeAndRefresh(t *testing.T) {
	sqlStores, err := NewSQLStores("sqlite", "file:"+t.TempDir()+"/oidc.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlStores.Close() })
	stores := sqlStores.AsStores()
	ctx := context.Background()

	code := AuthCode{
		ClientID: "c", RedirectURI: "https://x/cb", CodeChallenge: "ch",
		Scope: "openid", Sub: "user@example.com", AuthTime: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}
	require.NoError(t, stores.Codes.Put(ctx, "hash1", code))
	got, err := stores.Codes.Consume(ctx, "hash1")
	require.NoError(t, err)
	require.Equal(t, "c", got.ClientID)
	_, err = stores.Codes.Consume(ctx, "hash1")
	require.ErrorIs(t, err, ErrNotFound)

	rec := RefreshRecord{
		FamilyID: "fam", ClientID: "c", Sub: "user@example.com", Scope: "openid offline_access",
		AuthTime: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, stores.Refresh.Put(ctx, "rt1", rec))
	gotRT, err := stores.Refresh.Consume(ctx, "rt1")
	require.NoError(t, err)
	require.Equal(t, "fam", gotRT.FamilyID)
	_, err = stores.Refresh.Consume(ctx, "rt1")
	require.ErrorIs(t, err, ErrReuseDetected)
	require.NoError(t, stores.Refresh.RevokeFamily(ctx, "fam"))

	require.NoError(t, stores.Consents.Put(ctx, Consent{Sub: "user@example.com", ClientID: "c", Scope: "openid email"}))
	c, err := stores.Consents.Get(ctx, "user@example.com", "c")
	require.NoError(t, err)
	require.Equal(t, "openid email", c.Scope)
}

func completeLoginAndConsent(t *testing.T, handler http.Handler, jar *cookieJar, challenge, scope string) string {
	t.Helper()
	authQ := url.Values{
		"response_type":         {"code"},
		"client_id":             {"confidential"},
		"redirect_uri":          {"https://rp.example.test/callback"},
		"scope":                 {scope},
		"state":                 {"st"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rec := doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize?"+authQ.Encode(), nil)
	if rec.Header().Get("Location") == "/oidc-idp/login" {
		rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/login", nil)
		csrf := formValue(rec.Body.String(), "csrf")
		rec = doReq(t, handler, jar, http.MethodPost, "/oidc-idp/login", url.Values{
			"csrf": {csrf}, "email": {"user@example.com"}, "password": {"Password1!"},
		})
		rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/authorize", nil)
	}
	if rec.Header().Get("Location") == "/oidc-idp/consent" {
		rec = doReq(t, handler, jar, http.MethodGet, "/oidc-idp/consent", nil)
		csrf := formValue(rec.Body.String(), "csrf")
		rec = doReq(t, handler, jar, http.MethodPost, "/oidc-idp/consent", url.Values{
			"csrf": {csrf}, "decision": {"allow"},
		})
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

func tokenRequest(t *testing.T, handler http.Handler, form url.Values, clientID, secret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oidc-idp/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func formValue(html, name string) string {
	marker := `name="` + name + `"`
	i := strings.Index(html, marker)
	if i < 0 {
		return ""
	}
	slice := html[i:]
	const prefix = `value="`
	j := strings.Index(slice, prefix)
	if j < 0 {
		return ""
	}
	slice = slice[j+len(prefix):]
	k := strings.Index(slice, `"`)
	if k < 0 {
		return ""
	}
	return slice[:k]
}

func TestSignedOIDCTokenVerifies(t *testing.T) {
	testRSAEnv(t)
	signer, err := newTokenSignerFromEnv()
	require.NoError(t, err)
	tok, err := signer.signClaims(map[string]any{
		"iss": issuer(), "sub": "a", "aud": "c", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	})
	require.NoError(t, err)
	parsed, err := jwt.Parse([]byte(tok), jwt.WithKeySet(signer.verifySet), jwt.WithValidate(true))
	require.NoError(t, err)
	require.Equal(t, "a", parsed.Subject())
}
