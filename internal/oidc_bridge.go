package internal

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/antosara-dev/antosara-auth/pkg"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/crypto/bcrypt"
)

// CurrentUser implements oidc.SessionManager using the first-party auth_token cookie.
func (h *AuthHandler) CurrentUser(r *http.Request) (email, jti string, ok bool) {
	cookie, err := r.Cookie("auth_token")
	if err != nil || cookie.Value == "" {
		return "", "", false
	}
	if h.verifyKeySet == nil || h.verifyKeySet.Len() == 0 {
		return "", "", false
	}
	tok, err := jwt.ParseString(cookie.Value, jwt.WithKeySet(h.verifyKeySet), jwt.WithValidate(true))
	if err != nil || tok == nil {
		return "", "", false
	}

	if expectedIss := os.Getenv("JWT_ISSUER"); expectedIss != "" {
		if tok.Issuer() != expectedIss {
			return "", "", false
		}
	}
	if expectedType := os.Getenv("JWT_TYPE"); expectedType != "" {
		typ, _ := tok.Get("type")
		s, _ := typ.(string)
		if s != expectedType {
			return "", "", false
		}
	}
	if v, ok := tok.Get("email"); ok {
		email, _ = v.(string)
	}
	if email == "" {
		email = tok.Subject()
	}
	if email == "" {
		return "", "", false
	}
	if aud := tok.Audience(); len(aud) > 0 && !audContains(aud, email) {
		return "", "", false
	}
	jti = tok.JwtID()
	if jti == "" {
		return "", "", false
	}
	revoked, err := h.tokenRevokeRepo.IsTokenRevoked(r.Context(), jti)
	if err != nil || revoked {
		return "", "", false
	}
	return email, jti, true
}

// Establish implements oidc.SessionManager by minting the same first-party JWT cookies as /api/login.
func (h *AuthHandler) Establish(w http.ResponseWriter, r *http.Request, email string) error {
	tokenString, jti, expiresAt, err := CreateJWTToken(email)
	if err != nil {
		return err
	}
	setAuthCookie(w, tokenString)
	csrfToken, err := generateRandomString(32)
	if err != nil {
		return err
	}
	if err := h.csrfRepo.Put(r.Context(), jti, csrfToken, expiresAt); err != nil {
		return err
	}
	setCSRFCookie(w, csrfToken)
	return nil
}

// Destroy implements oidc.SessionManager using the same revocation + cookie-clear path as /api/logout.
func (h *AuthHandler) Destroy(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie("auth_token")
	if err == nil && cookie.Value != "" && h.verifyKeySet != nil {
		tok, parseErr := jwt.ParseString(cookie.Value, jwt.WithKeySet(h.verifyKeySet), jwt.WithValidate(false))
		if parseErr == nil && tok != nil {
			jti := tok.JwtID()
			if jti != "" {
				if err := h.csrfRepo.Delete(r.Context(), jti); err != nil {
					log.Printf("Failed to delete CSRF session: %v", err)
				}
				expiresAt := tok.Expiration()
				if expiresAt.IsZero() {
					expiresAt = time.Now().Add(24 * time.Hour)
				}
				if err := h.tokenRevokeRepo.RevokeToken(r.Context(), jti, expiresAt); err != nil {
					log.Printf("Failed to revoke token: %v", err)
				}
			}
		}
	}
	clearAuthCookie(w)
	clearCSRFCookie(w)
	return nil
}

// Authenticate implements oidc.SessionManager with the same credential and lockout rules as /api/login.
func (h *AuthHandler) Authenticate(ctx context.Context, email, password string) (*pkg.User, error) {
	normalized, err := validateEmail(email)
	if err != nil {
		return nil, pkg.ErrInvalidCredentials
	}

	user, getErr := h.userRepo.GetUserByEmail(ctx, normalized)
	var passwordHash []byte
	if getErr == nil && user != nil {
		passwordHash = []byte(user.Password)
	} else {
		dummyHash, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
		passwordHash = dummyHash
	}

	passwordErr := bcrypt.CompareHashAndPassword(passwordHash, []byte(password))
	if getErr != nil || passwordErr != nil {
		if getErr == nil && user != nil {
			if recordErr := h.recordFailedAttempt(normalized); recordErr != nil {
				log.Printf("Failed to record failed attempt: %v", recordErr)
			}
		}
		time.Sleep(100 * time.Millisecond)
		return nil, pkg.ErrInvalidCredentials
	}

	if err := h.checkAccountLockout(normalized); err != nil {
		return nil, err
	}
	if !user.Verified {
		return nil, pkg.ErrInvalidCredentials
	}
	if err := h.clearFailedAttempts(normalized); err != nil {
		log.Printf("Failed to clear failed attempts: %v", err)
	}
	return user, nil
}
