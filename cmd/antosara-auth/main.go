package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/antosara-dev/antosara-auth/internal"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// securityHeaders adds security headers to all responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Hardened CSP: removed 'unsafe-inline' from script-src to prevent XSS
		// If inline scripts are required, use nonces: script-src 'self' 'nonce-{random}' ...
		// For style-src, 'unsafe-inline' may be needed for some frameworks, but prefer nonces when possible
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:;")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

func main() {
	// Load environment variables FIRST (before initializing repositories)
	if err := internal.LoadEnv(); err != nil {
		log.Fatalf("Failed to load environment variables: %v", err)
	}

	// Initialize DynamoDB repositories AFTER loading environment variables
	userRepo, err := internal.NewDynamoDBUserRepository()
	if err != nil {
		log.Fatalf("Failed to initialize DynamoDB repository: %v", err)
	}

	tokenRevokeRepo, err := internal.NewDynamoDBTokenRevocationRepository()
	if err != nil {
		log.Fatalf("Failed to initialize token revocation repository: %v", err)
	}

	csrfRepo, err := internal.NewDynamoDBSessionCSRFRepository()
	if err != nil {
		log.Fatalf("Failed to initialize CSRF repository: %v", err)
	}

	// Create a new Chi router
	r := chi.NewRouter()

	// Add security headers middleware
	r.Use(securityHeaders)

	// Add CORS middleware
	// Build allowed origins: include HOST_NAME and any additional origins from CORS_ORIGINS env var
	allowedOrigins := []string{"https://" + os.Getenv("HOST_NAME")}
	if corsOrigins := os.Getenv("CORS_ORIGINS"); corsOrigins != "" {
		// CORS_ORIGINS can be comma-separated list: "https://app.domain.com,https://api.domain.com"
		origins := strings.Split(corsOrigins, ",")
		for _, origin := range origins {
			origin = strings.TrimSpace(origin)
			if origin != "" {
				allowedOrigins = append(allowedOrigins, origin)
			}
		}
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	// Add middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.CleanPath)
	r.Use(middleware.GetHead)
	r.Use(middleware.Throttle(100))
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.Timeout(60 * time.Second)) // Add request timeout

	mode := os.Getenv("MODE")
	if mode == "DEV" {
		log.Println("********* RUNNING IN DEV MODE *********")
		//r.Mount("/debug", middleware.Profiler())
	}

	// Initialize auth handler
	// For RS256: use JWT_PRIVATE_KEY (RSA private key in PEM format)
	jwtPrivateKey := os.Getenv("JWT_PRIVATE_KEY")
	if jwtPrivateKey == "" {
		log.Fatalf("JWT_PRIVATE_KEY (for RS256) must be set")
	}
	authHandler := internal.NewAuthHandler(jwtPrivateKey, userRepo, tokenRevokeRepo, csrfRepo)

	// Register all routes
	internal.RegisterRoutes(authHandler, r)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}
	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
