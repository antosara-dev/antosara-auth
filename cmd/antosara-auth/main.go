package main

import (
	"github.com/antosara-dev/antosara-auth/internal"
	"github.com/antosara-dev/antosara-auth/pkg"
	"log"
	"os"
	"time"

	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

var (
	userRepo         pkg.UserRepository
	tokenRevokeRepo  pkg.TokenRevocationRepository
)

func init() {
	// Initialize DynamoDB repositories
	var err error
	userRepo, err = internal.NewDynamoDBUserRepository()
	if err != nil {
		log.Fatalf("Failed to initialize DynamoDB repository: %v", err)
	}

	tokenRevokeRepo, err = internal.NewDynamoDBTokenRevocationRepository()
	if err != nil {
		log.Fatalf("Failed to initialize token revocation repository: %v", err)
	}
}

// securityHeaders adds security headers to all responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self' https://*.googleapis.com; script-src 'self' 'unsafe-inline' https://accounts.google.com https://apis.google.com https://*.googleapis.com https://cdn.jsdelivr.net; worker-src 'self' blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

func main() {
	// Load environment variables based on MODE
	if err := internal.LoadEnv(); err != nil {
		log.Fatalf("Failed to load environment variables: %v", err)
	}

	// Create a new Chi router
	r := chi.NewRouter()

	// Add security headers middleware
	r.Use(securityHeaders)

	// Add CORS middleware
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://" + os.Getenv("HOST_NAME"), "https://apis.google.com"},
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
	authHandler := internal.NewAuthHandler(os.Getenv("SECRET_KEY"), userRepo, tokenRevokeRepo)

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
