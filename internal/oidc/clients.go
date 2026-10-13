package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	AuthMethodBasic = "client_secret_basic"
	AuthMethodPost  = "client_secret_post"
	AuthMethodNone  = "none"

	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
)

// Client is a registered OIDC relying party.
type Client struct {
	ClientID                string
	ClientSecretHash        string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	Public                  bool
	TokenEndpointAuthMethod string
	GrantTypes              []string
}

// AllowsRedirect reports whether redirectURI is an exact registered redirect.
func (c *Client) AllowsRedirect(redirectURI string) bool {
	for _, u := range c.RedirectURIs {
		if u == redirectURI {
			return true
		}
	}
	return false
}

// AllowsPostLogoutRedirect reports whether uri is an exact registered logout redirect.
func (c *Client) AllowsPostLogoutRedirect(uri string) bool {
	for _, u := range c.PostLogoutRedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// AllowsGrant reports whether the client may use grantType.
func (c *Client) AllowsGrant(grantType string) bool {
	for _, g := range c.GrantTypes {
		if g == grantType {
			return true
		}
	}
	return false
}

// ClientRepository looks up relying parties. v1 is static config; a DB
// implementation can satisfy the same interface later.
type ClientRepository interface {
	GetByClientID(ctx context.Context, id string) (*Client, error)
}

// StaticClientRepository serves clients loaded at process start.
type StaticClientRepository struct {
	clients map[string]*Client
}

// GetByClientID implements ClientRepository.
func (r *StaticClientRepository) GetByClientID(_ context.Context, id string) (*Client, error) {
	if r == nil {
		return nil, ErrInvalidClient
	}
	c, ok := r.clients[id]
	if !ok {
		return nil, ErrInvalidClient
	}
	out := *c
	return &out, nil
}

type clientJSON struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	Public                  bool     `json:"public"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
}

// LoadClientsFromEnv reads OIDC_CLIENTS (JSON array) or OIDC_CLIENTS_FILE.
// OIDC_CLIENTS wins if both are set. An unset value yields an empty repository.
func LoadClientsFromEnv() (*StaticClientRepository, error) {
	raw := strings.TrimSpace(os.Getenv("OIDC_CLIENTS"))
	if raw == "" {
		path := strings.TrimSpace(os.Getenv("OIDC_CLIENTS_FILE"))
		if path == "" {
			return NewStaticClientRepository(nil)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read OIDC_CLIENTS_FILE: %w", err)
		}
		raw = string(b)
	}
	var specs []clientJSON
	if err := json.Unmarshal([]byte(raw), &specs); err != nil {
		return nil, fmt.Errorf("parse OIDC_CLIENTS: %w", err)
	}
	clients := make([]*Client, 0, len(specs))
	for i, spec := range specs {
		c, err := spec.toClient()
		if err != nil {
			return nil, fmt.Errorf("OIDC client[%d]: %w", i, err)
		}
		clients = append(clients, c)
	}
	return NewStaticClientRepository(clients)
}

// NewStaticClientRepository indexes clients by client_id.
func NewStaticClientRepository(clients []*Client) (*StaticClientRepository, error) {
	repo := &StaticClientRepository{clients: make(map[string]*Client, len(clients))}
	for _, c := range clients {
		if c == nil || c.ClientID == "" {
			return nil, fmt.Errorf("client_id is required")
		}
		if _, exists := repo.clients[c.ClientID]; exists {
			return nil, fmt.Errorf("duplicate client_id %q", c.ClientID)
		}
		copy := *c
		repo.clients[c.ClientID] = &copy
	}
	return repo, nil
}

func (spec clientJSON) toClient() (*Client, error) {
	id := strings.TrimSpace(spec.ClientID)
	if id == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if len(spec.RedirectURIs) == 0 {
		return nil, fmt.Errorf("redirect_uris is required")
	}

	method := strings.TrimSpace(spec.TokenEndpointAuthMethod)
	grants := append([]string(nil), spec.GrantTypes...)
	if len(grants) == 0 {
		grants = []string{GrantAuthorizationCode, GrantRefreshToken}
	}

	c := &Client{
		ClientID:                id,
		RedirectURIs:            append([]string(nil), spec.RedirectURIs...),
		PostLogoutRedirectURIs:  append([]string(nil), spec.PostLogoutRedirectURIs...),
		Public:                  spec.Public,
		TokenEndpointAuthMethod: method,
		GrantTypes:              grants,
	}

	if c.Public {
		if c.TokenEndpointAuthMethod == "" {
			c.TokenEndpointAuthMethod = AuthMethodNone
		}
		if c.TokenEndpointAuthMethod != AuthMethodNone {
			return nil, fmt.Errorf("public client must use token_endpoint_auth_method %q", AuthMethodNone)
		}
		return c, nil
	}

	if c.TokenEndpointAuthMethod == "" {
		c.TokenEndpointAuthMethod = AuthMethodBasic
	}
	switch c.TokenEndpointAuthMethod {
	case AuthMethodBasic, AuthMethodPost:
	default:
		return nil, fmt.Errorf("unsupported token_endpoint_auth_method %q", c.TokenEndpointAuthMethod)
	}

	secret := spec.ClientSecret
	if secret == "" {
		return nil, fmt.Errorf("client_secret is required for confidential clients")
	}
	if isBcryptHash(secret) {
		c.ClientSecretHash = secret
		return c, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash client_secret: %w", err)
	}
	c.ClientSecretHash = string(hash)
	return c, nil
}

func isBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}

func (c *Client) checkSecret(secret string) error {
	if c.Public {
		if secret != "" {
			return ErrInvalidClient
		}
		return nil
	}
	if c.ClientSecretHash == "" {
		return ErrInvalidClient
	}
	if err := bcrypt.CompareHashAndPassword([]byte(c.ClientSecretHash), []byte(secret)); err != nil {
		return ErrInvalidClient
	}
	return nil
}

const (
	envOIDCRP                 = "ENABLE_OIDC_RP"
	DevRPClientID             = "oidc-rp"
	DevRPConfidentialClientID = "oidc-rp-confidential"
	DevRPConfidentialSecret   = "oidc-rp-dev-secret"
)

// DevRPEnabled reports whether the local OIDC test relying party is opted in.
// Unset/empty is false. Truthy values: 1, true, yes, on (case-insensitive).
func DevRPEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envOIDCRP))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// Put adds or replaces a client in the static registry.
func (r *StaticClientRepository) Put(c *Client) error {
	if r == nil || r.clients == nil {
		return fmt.Errorf("client repository is not initialized")
	}
	if c == nil || c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	copy := *c
	r.clients[c.ClientID] = &copy
	return nil
}

// DevRPClient is the public PKCE client used by the localhost test relying party.
func DevRPClient(port string) *Client {
	if port == "" {
		port = "5000"
	}
	uris := []string{
		"http://localhost:" + port + "/oidc-rp",
		"http://127.0.0.1:" + port + "/oidc-rp",
	}
	return &Client{
		ClientID:                DevRPClientID,
		Public:                  true,
		RedirectURIs:            uris,
		PostLogoutRedirectURIs:  uris,
		TokenEndpointAuthMethod: AuthMethodNone,
		GrantTypes:              []string{GrantAuthorizationCode, GrantRefreshToken},
	}
}

// DevRPConfidentialClient is the confidential test RP (server-side token exchange).
func DevRPConfidentialClient(port string) (*Client, error) {
	if port == "" {
		port = "5000"
	}
	callback := []string{
		"http://localhost:" + port + "/oidc-rp/callback",
		"http://127.0.0.1:" + port + "/oidc-rp/callback",
	}
	home := []string{
		"http://localhost:" + port + "/oidc-rp",
		"http://127.0.0.1:" + port + "/oidc-rp",
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(DevRPConfidentialSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Client{
		ClientID:                DevRPConfidentialClientID,
		ClientSecretHash:        string(hash),
		Public:                  false,
		RedirectURIs:            callback,
		PostLogoutRedirectURIs:  home,
		TokenEndpointAuthMethod: AuthMethodBasic,
		GrantTypes:              []string{GrantAuthorizationCode, GrantRefreshToken},
	}, nil
}

// RegisterDevRPClient adds the public and confidential test RP clients when ENABLE_OIDC_RP is set.
func RegisterDevRPClient(repo *StaticClientRepository, port string) bool {
	if repo == nil || !DevRPEnabled() {
		return false
	}
	if err := repo.Put(DevRPClient(port)); err != nil {
		return false
	}
	conf, err := DevRPConfidentialClient(port)
	if err != nil {
		return false
	}
	if err := repo.Put(conf); err != nil {
		return false
	}
	return true
}
