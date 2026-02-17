// Package client provides helpers for other services to call the auth service API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultHTTPClient is the default client used by CheckRevoked (10s timeout).
var DefaultHTTPClient = &http.Client{Timeout: 10 * time.Second}

// CheckRevoked calls the auth service's revocation endpoint and returns whether
// the given jti (JWT ID claim) is revoked. baseURL is the auth service root
// (e.g. "https://auth.example.com"); it must not include a trailing slash.
// Use this after verifying the JWT locally (e.g. via JWKS) to enforce logout.
func CheckRevoked(ctx context.Context, baseURL, jti string) (revoked bool, err error) {
	return CheckRevokedWithClient(ctx, DefaultHTTPClient, baseURL, jti)
}

// CheckRevokedWithClient is like CheckRevoked but uses the provided *http.Client.
func CheckRevokedWithClient(ctx context.Context, c *http.Client, baseURL, jti string) (revoked bool, err error) {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return false, fmt.Errorf("jti is required")
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	url := baseURL + "/api/token/check-revocation"
	body := map[string]string{"jti": jti}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("auth service returned %d", resp.StatusCode)
	}
	var out struct {
		Revoked bool `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Revoked, nil
}
