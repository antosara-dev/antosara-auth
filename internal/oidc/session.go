package oidc

import (
	"context"
	"net/http"

	"github.com/antosara-dev/antosara-auth/pkg"
)

// SessionManager is implemented by the first-party auth handler so OIDC login
// can reuse /api sessions without changing /api routes or JWT claims.
type SessionManager interface {
	CurrentUser(r *http.Request) (email, jti string, ok bool)
	Establish(w http.ResponseWriter, r *http.Request, email string) error
	Destroy(w http.ResponseWriter, r *http.Request) error
	Authenticate(ctx context.Context, email, password string) (*pkg.User, error)
}
