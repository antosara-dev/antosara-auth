package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type tokenSigner struct {
	key       jwk.Key
	verifySet jwk.Set
	kid       string
}

func newTokenSignerFromEnv() (*tokenSigner, error) {
	privPEM := strings.TrimSpace(os.Getenv("JWT_PRIVATE_KEY"))
	if privPEM == "" {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY is required for OIDC token signing")
	}
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY is not valid PEM")
	}
	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = k
	} else {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse JWT_PRIVATE_KEY: %w", err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("JWT_PRIVATE_KEY is not an RSA private key")
		}
		priv = rsaKey
	}

	kid := rsaKid(&priv.PublicKey)
	signKey, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, fmt.Errorf("jwk from private key: %w", err)
	}
	if err := signKey.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := signKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return nil, err
	}

	pubKey, err := jwk.FromRaw(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	_ = pubKey.Set(jwk.KeyIDKey, kid)
	_ = pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
	set := jwk.NewSet()
	_ = set.AddKey(pubKey)

	if raw := strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY")); raw != "" {
		if extra, err := publicPEMToJWK(raw); err == nil {
			_ = set.AddKey(extra)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEYS")); raw != "" {
		rest := []byte(raw)
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			if extra, err := publicPEMToJWK(string(pem.EncodeToMemory(block))); err == nil {
				_ = set.AddKey(extra)
			}
			rest = remaining
		}
	}

	return &tokenSigner{key: signKey, verifySet: set, kid: kid}, nil
}

func publicPEMToJWK(pemStr string) (jwk.Key, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid public pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		pk, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
		if err2 != nil {
			return nil, err
		}
		pub = pk
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not rsa public key")
	}
	k, err := jwk.FromRaw(rsaPub)
	if err != nil {
		return nil, err
	}
	_ = k.Set(jwk.KeyIDKey, rsaKid(rsaPub))
	_ = k.Set(jwk.AlgorithmKey, jwa.RS256)
	return k, nil
}

func rsaKid(pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	h := sha256.New()
	_, _ = h.Write([]byte(n))
	_, _ = h.Write([]byte("."))
	_, _ = h.Write([]byte(e))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (s *tokenSigner) signClaims(claims map[string]any) (string, error) {
	tok := jwt.New()
	for k, v := range claims {
		if err := tok.Set(k, v); err != nil {
			return "", fmt.Errorf("set claim %s: %w", k, err)
		}
	}
	payload, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, s.key))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return string(payload), nil
}

func (s *tokenSigner) parse(token string) (jwt.Token, error) {
	tok, err := jwt.ParseString(token, jwt.WithKeySet(s.verifySet), jwt.WithValidate(true))
	if err != nil {
		return nil, err
	}
	return tok, nil
}

type mintedTokens struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresIn    int
	Scope        string
}

type mintInput struct {
	Sub         string
	ClientID    string
	Scope       string
	Nonce       string
	AuthTime    time.Time
	Email       string
	Alias       string
	Verified    bool
	FamilyID    string
	SessionJTI  string
	WithRefresh bool
}

func (h *Handler) mintTokens(in mintInput) (mintedTokens, RefreshRecord, error) {
	now := time.Now()
	accessExp := now.Add(accessTokenTTL())
	idExp := now.Add(idTokenTTL())
	scopes := splitScopes(in.Scope)

	accessJTI := uuid.NewString()
	accessClaims := map[string]any{
		"iss":       issuer(),
		"sub":       in.Sub,
		"aud":       issuer(),
		"exp":       accessExp.Unix(),
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"jti":       accessJTI,
		"client_id": in.ClientID,
		"scope":     in.Scope,
		"token_use": "access",
		"auth_time": in.AuthTime.Unix(),
	}
	accessToken, err := h.signer.signClaims(accessClaims)
	if err != nil {
		return mintedTokens{}, RefreshRecord{}, err
	}

	idClaims := map[string]any{
		"iss":       issuer(),
		"sub":       in.Sub,
		"aud":       in.ClientID,
		"exp":       idExp.Unix(),
		"iat":       now.Unix(),
		"auth_time": in.AuthTime.Unix(),
		"at_hash":   atHash(accessToken),
	}
	if in.Nonce != "" {
		idClaims["nonce"] = in.Nonce
	}
	if hasScope(scopes, "email") {
		idClaims["email"] = in.Email
		idClaims["email_verified"] = in.Verified
	}
	if hasScope(scopes, "profile") {
		name := in.Alias
		if name == "" {
			name = in.Email
		}
		idClaims["name"] = name
		idClaims["preferred_username"] = name
	}
	idToken, err := h.signer.signClaims(idClaims)
	if err != nil {
		return mintedTokens{}, RefreshRecord{}, err
	}

	out := mintedTokens{
		AccessToken: accessToken,
		IDToken:     idToken,
		ExpiresIn:   int(accessTokenTTL().Seconds()),
		Scope:       in.Scope,
	}

	var rec RefreshRecord
	if in.WithRefresh && hasScope(scopes, "offline_access") {
		rt, err := randomToken(32)
		if err != nil {
			return mintedTokens{}, RefreshRecord{}, err
		}
		family := in.FamilyID
		if family == "" {
			family = uuid.NewString()
		}
		rec = RefreshRecord{
			FamilyID:   family,
			ClientID:   in.ClientID,
			Sub:        in.Sub,
			Scope:      in.Scope,
			SessionJTI: in.SessionJTI,
			AuthTime:   in.AuthTime,
			ExpiresAt:  now.Add(refreshTokenTTL()),
		}
		out.RefreshToken = rt
	}

	return out, rec, nil
}
