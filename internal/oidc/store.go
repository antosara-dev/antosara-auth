package oidc

import (
	"context"
	"time"
)

// AuthCode is a one-time authorization code bound to the original request.
type AuthCode struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Nonce         string
	Scope         string
	Sub           string
	SessionJTI    string
	AuthTime      time.Time
	ExpiresAt     time.Time
}

// RefreshRecord is a hashed refresh token in a rotation family.
type RefreshRecord struct {
	FamilyID   string
	ClientID   string
	Sub        string
	Scope      string
	SessionJTI string
	AuthTime   time.Time
	ExpiresAt  time.Time
	Consumed   bool
}

// Consent is the set of scopes a user granted to a client.
type Consent struct {
	Sub      string
	ClientID string
	Scope    string
}

// CodeStore stores hashed authorization codes.
type CodeStore interface {
	Put(ctx context.Context, codeHash string, code AuthCode) error
	Consume(ctx context.Context, codeHash string) (*AuthCode, error)
}

// RefreshStore stores hashed refresh tokens and rotation families.
type RefreshStore interface {
	Put(ctx context.Context, tokenHash string, rec RefreshRecord) error
	Consume(ctx context.Context, tokenHash string) (*RefreshRecord, error)
	RevokeFamily(ctx context.Context, familyID string) error
	RevokeBySub(ctx context.Context, sub string) error
}

// ConsentStore persists per-user, per-client granted scopes.
type ConsentStore interface {
	Get(ctx context.Context, sub, clientID string) (*Consent, error)
	Put(ctx context.Context, c Consent) error
}

// Stores groups the OIDC persistence interfaces.
type Stores struct {
	Codes    CodeStore
	Refresh  RefreshStore
	Consents ConsentStore
}

func scopesGranted(granted, requested []string) bool {
	set := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		set[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
