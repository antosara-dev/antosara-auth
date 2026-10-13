package oidc

import (
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultIDTokenTTL      = 15 * time.Minute
	defaultAccessTokenTTL  = time.Hour
	defaultAuthCodeTTL     = 60 * time.Second
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
	defaultPendingTTL      = 10 * time.Minute
)

func issuer() string {
	if v := strings.TrimSpace(os.Getenv("OIDC_ISSUER")); v != "" {
		return strings.TrimRight(v, "/")
	}
	host := strings.TrimSpace(os.Getenv("HOST_NAME"))
	if host == "" {
		host = "localhost"
	}
	return "https://" + host + "/oidc-idp"
}

func jwksURI() string {
	u, err := url.Parse(issuer())
	if err != nil || u.Host == "" {
		return "/.well-known/jwks.json"
	}
	return u.Scheme + "://" + u.Host + "/.well-known/jwks.json"
}

func origin() string {
	u, err := url.Parse(issuer())
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return fallback
}

func idTokenTTL() time.Duration {
	return envDuration("OIDC_ID_TOKEN_TTL", defaultIDTokenTTL)
}

func accessTokenTTL() time.Duration {
	return envDuration("OIDC_ACCESS_TOKEN_TTL", defaultAccessTokenTTL)
}

func authCodeTTL() time.Duration {
	return envDuration("OIDC_AUTH_CODE_TTL", defaultAuthCodeTTL)
}

func refreshTokenTTL() time.Duration {
	return envDuration("OIDC_REFRESH_TOKEN_TTL", defaultRefreshTokenTTL)
}

func pendingTTL() time.Duration {
	return envDuration("OIDC_PENDING_TTL", defaultPendingTTL)
}
