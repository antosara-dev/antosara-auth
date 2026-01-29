package internal

import (
	"log"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
)

// RegisterRoutes registers all application routes
func RegisterRoutes(authHandler *AuthHandler, r chi.Router) {

	wd, err := os.Getwd()
	if err != nil {
		log.Printf("Error getting working directory: %v", err)
	}

	// Standards-based public JWKS endpoint (rate-limited)
	r.Group(func(r chi.Router) {
		r.Use(authHandler.RateLimitMiddleware)
		r.Get("/.well-known/jwks.json", authHandler.JWKS)
	})

	// If we're in cmd/antosara, go up two levels to reach project root
	if filepath.Base(wd) == "antosara" && filepath.Base(filepath.Dir(wd)) == "cmd" {
		wd = filepath.Dir(filepath.Dir(wd))
	}

	// API routes
	r.Route("/api", func(r chi.Router) {
		// Rate limiting for authentication endpoints
		r.Group(func(r chi.Router) {
			r.Use(authHandler.RateLimitMiddleware)
			// Auth routes
			r.Post("/signup", authHandler.Signup)
			r.Post("/verify-email", authHandler.VerifyEmail)
			r.Post("/login", authHandler.Login)
			// Token verification (public, rate-limited)
			r.Post("/verify-token", authHandler.VerifyToken)
			r.Post("/reset-password", authHandler.ResetPassword)
			r.Post("/reset-password/confirm", authHandler.ConfirmResetPassword)
		})
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		// Extract token from cookie and set in Authorization header
		r.Use(authHandler.CookieTokenExtractor)
		// Seek, verify and validate JWT tokens (RS256 only, key-set verification for rotation)
		r.Use(authHandler.MultiKeyVerifier)
		// Validate JWT claims (issuer/audience/type)
		r.Use(authHandler.ValidateJWTClaims)
		// Check if token is revoked
		r.Use(authHandler.TokenRevocationChecker)
		// Authenticate the token
		r.Use(jwtauth.Authenticator(authHandler.tokenAuth))
		// CSRF protection for cookie-based auth (session-bound, rotating)
		r.Use(authHandler.CSRFProtector)

		// Protected API routes
		r.Route("/api/profile", func(r chi.Router) {
			r.Get("/", authHandler.Profile)
			r.Put("/", authHandler.Profile)
		})

		// Add logout route
		r.Post("/api/logout", authHandler.Logout)
	})
}
