package internal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/antosara-dev/antosara-auth/pkg"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// AuthHandler handles authentication related operations
type AuthHandler struct {
	tokenAuth       *jwtauth.JWTAuth
	userRepo        pkg.UserRepository
	tokenRevokeRepo pkg.TokenRevocationRepository
	csrfRepo        pkg.SessionCSRFRepository
	router          chi.Router
	mu              sync.RWMutex
	rateLimiters    map[string]*rate.Limiter
	rateLimiterMu   sync.RWMutex
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(secretKey string, userRepo pkg.UserRepository, tokenRevokeRepo pkg.TokenRevocationRepository, csrfRepo pkg.SessionCSRFRepository) *AuthHandler {
	return &AuthHandler{
		tokenAuth:       jwtauth.New(os.Getenv("JWT_ALGORITHM"), []byte(secretKey), nil),
		userRepo:        userRepo,
		tokenRevokeRepo: tokenRevokeRepo,
		csrfRepo:        csrfRepo,
		router:          chi.NewRouter(),
		rateLimiters:    make(map[string]*rate.Limiter),
	}
}

// getRateLimiter returns or creates a rate limiter for the given IP address
func (h *AuthHandler) getRateLimiter(ip string) *rate.Limiter {
	h.rateLimiterMu.RLock()
	limiter, exists := h.rateLimiters[ip]
	h.rateLimiterMu.RUnlock()

	if !exists {
		// Default: 5 requests per minute per IP (configurable via env)
		requestsPerMinute := 5
		if s := os.Getenv("RATE_LIMIT_REQUESTS_PER_MINUTE"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v > 0 {
				requestsPerMinute = v
			}
		}
		limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerMinute)), requestsPerMinute)

		h.rateLimiterMu.Lock()
		h.rateLimiters[ip] = limiter
		h.rateLimiterMu.Unlock()
	}

	return limiter
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for proxies/load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		// If it's a comma-separated list, take the first IP
		for idx := 0; idx < len(xff); idx++ {
			if xff[idx] == ',' {
				firstIP := xff[:idx]
				if ip := net.ParseIP(firstIP); ip != nil {
					return ip.String()
				}
				break
			}
		}
		// If no comma found, try parsing the whole string
		if ip := net.ParseIP(xff); ip != nil {
			return ip.String()
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String()
		}
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// RateLimitMiddleware enforces per-IP rate limiting on authentication endpoints
func (h *AuthHandler) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		limiter := h.getRateLimiter(clientIP)

		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetTokenAuth returns the JWT auth instance
func (h *AuthHandler) GetTokenAuth() *jwtauth.JWTAuth {
	return h.tokenAuth
}

// setAuthCookie sets a secure httpOnly cookie with the JWT token
func setAuthCookie(w http.ResponseWriter, token string) {
	// Get expiry hours from environment
	expiryHours := 24 // Default to 24 hours if not set
	if expiryStr := os.Getenv("JWT_EXPIRY_HOURS"); expiryStr != "" {
		if hours, err := strconv.Atoi(expiryStr); err == nil && hours > 0 {
			expiryHours = hours
		}
	}

	// Always use Secure flag for cookies (requires HTTPS)
	secure := true

	// For cross-subdomain support (e.g., app.domain.com <-> auth.domain.com)
	// Set Domain to parent domain (e.g., ".domain.com") if COOKIE_DOMAIN is set
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	// Use SameSiteLaxMode for cross-subdomain cookie support
	// Lax allows cookies on top-level navigations (e.g., OAuth redirects) but blocks CSRF on POST requests
	sameSite := http.SameSiteLaxMode
	if cookieDomain == "" {
		// If no cross-subdomain needed, use Strict for better CSRF protection
		sameSite = http.SameSiteStrictMode
	}

	cookie := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		MaxAge:   expiryHours * 3600, // Convert hours to seconds
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	}
	if cookieDomain != "" {
		cookie.Domain = cookieDomain // e.g., ".domain.com" for cross-subdomain access
	}
	http.SetCookie(w, cookie)
}

func setCSRFCookie(w http.ResponseWriter, token string) {
	secure := true // Always use Secure flag for cookies (requires HTTPS)
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	sameSite := http.SameSiteLaxMode
	if cookieDomain == "" {
		sameSite = http.SameSiteStrictMode
	}
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		MaxAge:   24 * 3600,
		HttpOnly: false, // must be readable by browser JS to send X-CSRF-Token header
		Secure:   secure,
		SameSite: sameSite,
	}
	if cookieDomain != "" {
		cookie.Domain = cookieDomain
	}
	http.SetCookie(w, cookie)
}

// clearAuthCookie clears the authentication cookie
func clearAuthCookie(w http.ResponseWriter) {
	secure := true // Always use Secure flag for cookies (requires HTTPS)
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	sameSite := http.SameSiteLaxMode
	if cookieDomain == "" {
		sameSite = http.SameSiteStrictMode
	}
	cookie := &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	}
	if cookieDomain != "" {
		cookie.Domain = cookieDomain
	}
	http.SetCookie(w, cookie)
}

func clearCSRFCookie(w http.ResponseWriter) {
	secure := true // Always use Secure flag for cookies (requires HTTPS)
	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	sameSite := http.SameSiteLaxMode
	if cookieDomain == "" {
		sameSite = http.SameSiteStrictMode
	}
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   secure,
		SameSite: sameSite,
	}
	if cookieDomain != "" {
		cookie.Domain = cookieDomain
	}
	http.SetCookie(w, cookie)
}

// CookieTokenExtractor is a middleware that extracts JWT token from cookie
// and sets it in the Authorization header for jwtauth to process
func (h *AuthHandler) CookieTokenExtractor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if Authorization header is already set
		if r.Header.Get("Authorization") == "" {
			// Try to get token from cookie
			cookie, err := r.Cookie("auth_token")
			if err == nil && cookie.Value != "" {
				// Set the token in Authorization header for jwtauth
				r.Header.Set("Authorization", "Bearer "+cookie.Value)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// TokenRevocationChecker is a middleware that checks if a JWT token has been revoked
func (h *AuthHandler) TokenRevocationChecker(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from context (set by jwtauth.Verifier)
		token, claims, err := jwtauth.FromContext(r.Context())
		if err != nil || token == nil {
			// If no token, let jwtauth.Authenticator handle it
			next.ServeHTTP(w, r)
			return
		}

		// Extract JTI (JWT ID) from claims
		jti, ok := claims["jti"].(string)
		if !ok || jti == "" {
			// If no JTI, reject the token
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check if token is revoked
		revoked, err := h.tokenRevokeRepo.IsTokenRevoked(r.Context(), jti)
		if err != nil {
			log.Printf("Failed to check token revocation: %v", err)
			// Fail closed: if we can't validate revocation status, don't accept the token.
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}

		if revoked {
			http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ValidateJWTClaims validates issuer/audience/type claims.
// NOTE: jwtauth.Verifier already validated signature and standard time claims.
func (h *AuthHandler) ValidateJWTClaims(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, claims, err := jwtauth.FromContext(r.Context())
		if err != nil || token == nil {
			// Let jwtauth.Authenticator handle missing/invalid tokens.
			next.ServeHTTP(w, r)
			return
		}

		// Validate issuer if configured
		if expectedIss := os.Getenv("JWT_ISSUER"); expectedIss != "" {
			iss, _ := claims["iss"].(string)
			if iss != expectedIss {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
		}

		// Validate type if configured
		if expectedType := os.Getenv("JWT_TYPE"); expectedType != "" {
			typ, _ := claims["type"].(string)
			if typ != expectedType {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
		}

		// Validate audience: must contain the token's email (we mint aud=email)
		email, _ := claims["email"].(string)
		if email == "" {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		if aud, ok := claims["aud"]; ok {
			if !audContains(aud, email) {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func audContains(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, it := range v {
			if s, ok := it.(string); ok && s == expected {
				return true
			}
		}
		return false
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// CSRFProtector enforces session-bound CSRF with rotation.
// - Binds CSRF token to the authenticated session (JWT jti) by storing it server-side.
// - Requires X-CSRF-Token to match the cookie+server value on unsafe methods.
// - Rotates CSRF token on every non-OPTIONS request.
func (h *AuthHandler) CSRFProtector(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Only enforce CSRF for cookie-based sessions.
		// Non-browser / API clients using Authorization: Bearer (no auth_token cookie) are not subject to CSRF.
		if _, err := r.Cookie("auth_token"); err != nil {
			next.ServeHTTP(w, r)
			return
		}

		_, claims, err := jwtauth.FromContext(r.Context())
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		jti, _ := claims["jti"].(string)
		if jti == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		csrfCookie, err := r.Cookie("csrf_token")
		if err != nil || csrfCookie.Value == "" {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}

		sessionCSRF, err := h.csrfRepo.Get(r.Context(), jti)
		if err != nil || sessionCSRF == nil || sessionCSRF.Token == "" {
			http.Error(w, "CSRF token invalid", http.StatusForbidden)
			return
		}

		// Always require cookie to match server.
		if csrfCookie.Value != sessionCSRF.Token {
			http.Error(w, "CSRF token invalid", http.StatusForbidden)
			return
		}

		// On unsafe methods, require header match too.
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			// no header required
		default:
			csrfHeader := r.Header.Get("X-CSRF-Token")
			if csrfHeader == "" || csrfHeader != csrfCookie.Value {
				http.Error(w, "CSRF token invalid", http.StatusForbidden)
				return
			}
		}

		// Rotate token for next request
		nextToken, err := generateRandomString(32)
		if err != nil {
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := h.csrfRepo.Put(r.Context(), jti, nextToken, sessionCSRF.ExpiresAt); err != nil {
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		setCSRFCookie(w, nextToken)

		next.ServeHTTP(w, r)
	})
}

// CreateJWTToken creates a new JWT token with enhanced security claims
func CreateJWTToken(email string) (tokenString string, jti string, expiresAt time.Time, err error) {
	// Get secret key from environment
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		return "", "", time.Time{}, fmt.Errorf("SECRET_KEY environment variable not set")
	}

	// Get expiry hours from environment
	expiryHours := 24 // Default to 24 hours if not set
	if expiryStr := os.Getenv("JWT_EXPIRY_HOURS"); expiryStr != "" {
		if hours, err := strconv.Atoi(expiryStr); err == nil && hours > 0 {
			expiryHours = hours
		}
	}

	// Create new JWT auth with secret key
	tokenAuth := jwtauth.New(os.Getenv("JWT_ALGORITHM"), []byte(secretKey), nil)

	// Current time
	now := time.Now()
	jti = uuid.New().String()
	expiresAt = now.Add(time.Duration(expiryHours) * time.Hour)

	// Generate JWT token with enhanced security claims
	_, tokenString, err = tokenAuth.Encode(map[string]interface{}{
		// Standard claims
		"sub": email,            // Subject (user identifier)
		"iat": now.Unix(),       // Issued At
		"exp": expiresAt.Unix(), // Expiration Time
		"nbf": now.Unix(),       // Not Before
		"jti": jti,              // JWT ID (unique identifier for the token)

		// Custom claims
		"email": email,                   // User's email
		"iss":   os.Getenv("JWT_ISSUER"), // Issuer
		"aud":   email,                   // Audience (specific to the user)
		"type":  os.Getenv("JWT_TYPE"),   // Token type
	})

	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to create JWT token: %v", err)
	}

	return tokenString, jti, expiresAt, nil
}

// validateEmail validates email format and length, returns normalized email
func validateEmail(email string) (string, error) {
	// Trim whitespace and convert to lowercase
	email = strings.TrimSpace(strings.ToLower(email))

	// Check length (RFC 5321: local part max 64 chars, domain max 255 chars, total max 254)
	if len(email) == 0 {
		return "", fmt.Errorf("email is required")
	}
	if len(email) > 254 {
		return "", fmt.Errorf("email must be 254 characters or less")
	}
	if utf8.RuneCountInString(email) != len(email) {
		return "", fmt.Errorf("email contains invalid characters")
	}

	// Validate email format using net/mail
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", fmt.Errorf("invalid email format")
	}

	// Return normalized email (lowercase, trimmed)
	return strings.ToLower(addr.Address), nil
}

// validatePassword checks password complexity and length
func validatePassword(password string) error {
	// Check length
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if len(password) > 128 {
		return fmt.Errorf("password must be 128 characters or less")
	}

	// Check for valid UTF-8
	if !utf8.ValidString(password) {
		return fmt.Errorf("password contains invalid characters")
	}

	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case char == '!' || char == '@' || char == '#' || char == '$' || char == '%' || char == '^' || char == '&' || char == '*':
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
	}

	return nil
}

func generateVerificationCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// checkAccountLockout checks if an account is locked out
func (h *AuthHandler) checkAccountLockout(email string) error {
	user, err := h.userRepo.GetUserByEmail(context.Background(), email)
	if err != nil {
		return err
	}

	if !user.LockoutUntil.IsZero() && time.Now().Before(user.LockoutUntil) {
		remainingLockout := time.Until(user.LockoutUntil).Minutes()
		return fmt.Errorf("Account is locked. Try again after %.0f minutes", remainingLockout)
	}

	// Clear lockout if it has expired
	if !user.LockoutUntil.IsZero() && time.Now().After(user.LockoutUntil) {
		user.FailedAttempts = 0
		user.LockoutUntil = time.Time{}
		if err := h.userRepo.UpdateUser(context.Background(), user); err != nil {
			return err
		}
	}
	return nil
}

// recordFailedAttempt records a failed login attempt
func (h *AuthHandler) recordFailedAttempt(email string) error {
	user, err := h.userRepo.GetUserByEmail(context.Background(), email)
	if err != nil {
		return err
	}

	user.FailedAttempts++
	if user.FailedAttempts >= 5 {
		// Lock account for 15 minutes
		user.LockoutUntil = time.Now().Add(15 * time.Minute)
	}

	return h.userRepo.UpdateUser(context.Background(), user)
}

// clearFailedAttempts clears failed login attempts
func (h *AuthHandler) clearFailedAttempts(email string) error {
	user, err := h.userRepo.GetUserByEmail(context.Background(), email)
	if err != nil {
		return err
	}

	user.FailedAttempts = 0
	user.LockoutUntil = time.Time{}
	return h.userRepo.UpdateUser(context.Background(), user)
}

// Login handles user login and token generation
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate and normalize email format
	normalizedEmail, err := validateEmail(loginData.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	loginData.Email = normalizedEmail

	// Get user from database (don't reveal if user exists or not)
	user, err := h.userRepo.GetUserByEmail(r.Context(), loginData.Email)

	// Always perform password comparison to prevent timing attacks
	// Use a dummy hash if user doesn't exist
	var passwordHash []byte
	if err == nil && user != nil {
		passwordHash = []byte(user.Password)
	} else {
		// Use a dummy hash with same cost to prevent timing attacks
		dummyHash, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
		passwordHash = dummyHash
	}

	// Compare password (constant-time operation)
	passwordErr := bcrypt.CompareHashAndPassword(passwordHash, []byte(loginData.Password))

	// If user doesn't exist or password is wrong, return generic error
	if err != nil || passwordErr != nil {
		// Only record failed attempt if user exists (prevents enumeration)
		if err == nil && user != nil {
			if recordErr := h.recordFailedAttempt(loginData.Email); recordErr != nil {
				log.Printf("Failed to record failed attempt: %v", recordErr)
			}
		}
		// Add constant-time delay to prevent timing attacks
		time.Sleep(100 * time.Millisecond)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// User exists and password is correct - now check account lockout
	if err := h.checkAccountLockout(loginData.Email); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	// Check if email is verified (only reveal this after password is confirmed)
	// Still return generic error to prevent enumeration
	if !user.Verified {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Clear failed attempts on successful login
	if err := h.clearFailedAttempts(loginData.Email); err != nil {
		log.Printf("Failed to clear failed attempts: %v", err)
	}

	// Generate JWT token
	tokenString, jti, expiresAt, err := CreateJWTToken(user.Email)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Set secure httpOnly cookie with the token
	setAuthCookie(w, tokenString)
	// Initialize session-bound CSRF token
	csrfToken, err := generateRandomString(32)
	if err != nil {
		log.Printf("Failed to generate CSRF token: %v", err)
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}
	if err := h.csrfRepo.Put(r.Context(), jti, csrfToken, expiresAt); err != nil {
		log.Printf("Failed to store CSRF token: %v", err)
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}
	setCSRFCookie(w, csrfToken)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login successful",
	})
}

// Signup handles user registration
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var signupData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&signupData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate and normalize email format
	normalizedEmail, err := validateEmail(signupData.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	signupData.Email = normalizedEmail

	// Validate password complexity
	if err := validatePassword(signupData.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if user exists
	existingUser, err := h.userRepo.GetUserByEmail(r.Context(), signupData.Email)
	if err == nil {
		// User exists
		if existingUser.Verified {
			// Don't reveal if email exists - return generic error
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// User exists but not verified - update verification code and resend email
		verificationCode, err := generateVerificationCode()
		if err != nil {
			log.Printf("Failed to generate verification code: %v", err)
			http.Error(w, "Error generating verification code", http.StatusInternalServerError)
			return
		}
		existingUser.VerificationCode = verificationCode
		// Default verification-code expiry: 24 hours (override with VERIFICATION_CODE_EXPIRY_MINUTES)
		verificationExpiryMinutes := 24 * 60
		if s := os.Getenv("VERIFICATION_CODE_EXPIRY_MINUTES"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v > 0 {
				verificationExpiryMinutes = v
			}
		}
		existingUser.VerificationCodeExpiry = time.Now().Add(time.Duration(verificationExpiryMinutes) * time.Minute)

		// Hash the new password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signupData.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error processing password", http.StatusInternalServerError)
			return
		}
		existingUser.Password = string(hashedPassword)

		// Send verification email
		if err := sendVerificationEmail(existingUser.Email, verificationCode); err != nil {
			http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
			return
		}

		// Update user in database
		if err := h.userRepo.UpdateUser(r.Context(), existingUser); err != nil {
			http.Error(w, "Failed to update user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Verification code resent",
			"email":   existingUser.Email,
		})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signupData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	// Create new user
	verificationCode, err := generateVerificationCode()
	if err != nil {
		log.Printf("Failed to generate verification code: %v", err)
		http.Error(w, "Error generating verification code", http.StatusInternalServerError)
		return
	}
	verificationExpiryMinutes := 24 * 60
	if s := os.Getenv("VERIFICATION_CODE_EXPIRY_MINUTES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			verificationExpiryMinutes = v
		}
	}
	user := &pkg.User{
		Email:                  signupData.Email,
		Password:               string(hashedPassword),
		VerificationCode:       verificationCode,
		VerificationCodeExpiry: time.Now().Add(time.Duration(verificationExpiryMinutes) * time.Minute),
	}

	if err := h.userRepo.CreateUser(r.Context(), user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send verification email
	if err := sendVerificationEmail(user.Email, user.VerificationCode); err != nil {
		http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User created successfully. Please check your email for verification.",
		"email":   user.Email,
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get token from context (set by jwtauth.Verifier)
	token, claims, err := jwtauth.FromContext(r.Context())
	if err == nil && token != nil {
		// Extract JTI (JWT ID) from claims
		if jti, ok := claims["jti"].(string); ok && jti != "" {
			// Clear session-bound CSRF token (best-effort)
			if err := h.csrfRepo.Delete(r.Context(), jti); err != nil {
				log.Printf("Failed to delete CSRF session: %v", err)
			}

			// Extract expiration time from claims
			var expiresAt time.Time
			if exp, ok := claims["exp"].(float64); ok {
				expiresAt = time.Unix(int64(exp), 0)
			} else {
				// Default to 24 hours from now if exp is not available
				expiresAt = time.Now().Add(24 * time.Hour)
			}

			// Revoke the token
			if err := h.tokenRevokeRepo.RevokeToken(r.Context(), jti, expiresAt); err != nil {
				log.Printf("Failed to revoke token: %v", err)
				// Continue with logout even if revocation fails
			}
		}
	}

	// Clear the authentication cookie
	clearAuthCookie(w)
	clearCSRFCookie(w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

func (h *AuthHandler) VerifyToken(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token verified successfully"))
}

// VerifyEmail handles email verification using email, password and verification code
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var verifyData struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		VerificationCode string `json:"verification_code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&verifyData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate and normalize email format
	normalizedEmail, err := validateEmail(verifyData.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	verifyData.Email = normalizedEmail

	// Validate password
	if err := validatePassword(verifyData.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate verification code format (6 digits)
	verifyData.VerificationCode = strings.TrimSpace(verifyData.VerificationCode)
	if len(verifyData.VerificationCode) != 6 {
		http.Error(w, "Invalid verification code format", http.StatusBadRequest)
		return
	}
	for _, r := range verifyData.VerificationCode {
		if r < '0' || r > '9' {
			http.Error(w, "Invalid verification code format", http.StatusBadRequest)
			return
		}
	}

	// Get user from database
	user, err := h.userRepo.GetUserByEmail(r.Context(), verifyData.Email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(verifyData.Password))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Check if user is already verified
	if user.Verified {
		// Don't reveal verification status - return generic error
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify the code
	if user.VerificationCode != verifyData.VerificationCode {
		http.Error(w, "Invalid verification code", http.StatusBadRequest)
		return
	}
	// Enforce verification code expiry
	if user.VerificationCodeExpiry.IsZero() || time.Now().After(user.VerificationCodeExpiry) {
		http.Error(w, "Verification code expired", http.StatusBadRequest)
		return
	}

	// Update user verification status
	user.Verified = true
	user.VerificationCode = "" // Clear the verification code
	user.VerificationCodeExpiry = time.Time{}

	// Save the updated user
	err = h.userRepo.UpdateUser(r.Context(), user)
	if err != nil {
		http.Error(w, "Failed to update verification status", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"message": "Email verified successfully"}`)
}

// generateRandomString creates a random string of specified length
func generateRandomString(length int) (string, error) {
	// Generate cryptographically-secure random bytes and encode as URL-safe base64.
	// We then truncate to the requested length for stable token sizes.
	if length <= 0 {
		return "", fmt.Errorf("length must be > 0")
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(b)
	if len(s) < length {
		// Shouldn't happen for base64 encoding, but guard anyway.
		return "", fmt.Errorf("failed to generate token")
	}
	return s[:length], nil
}

// ResetPassword handles password reset requests
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate and normalize email format
	normalizedEmail, err := validateEmail(req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Email = normalizedEmail

	// Check if user exists
	user, err := h.userRepo.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Don't reveal if user exists or not
		http.Error(w, "If your email is registered, you will receive a password reset link", http.StatusOK)
		return
	}

	// Generate a random reset token
	resetToken, err := generateRandomString(32)
	if err != nil {
		log.Printf("Failed to generate reset token: %v", err)
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}
	user.ResetToken = resetToken
	// Default reset-token expiry: 60 minutes (override with RESET_TOKEN_EXPIRY_MINUTES)
	expiryMinutes := 60
	if s := os.Getenv("RESET_TOKEN_EXPIRY_MINUTES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			expiryMinutes = v
		}
	}
	user.ResetTokenExpiry = time.Now().Add(time.Duration(expiryMinutes) * time.Minute)

	// Update user with reset token
	if err := h.userRepo.UpdateUser(r.Context(), user); err != nil {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	// Send password reset email
	go func(email, token string) {
		if err := sendPasswordResetEmail(email, token); err != nil {
			// Don't log email addresses (PII protection)
			log.Printf("Failed to send password reset email: %v", err)
		}
	}(user.Email, resetToken)

	// Return success message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("If your email is registered, you will receive a password reset link"))
}

// ConfirmResetPassword handles setting a new password with a reset token
func (h *AuthHandler) ConfirmResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate reset token format (base64 URL-safe, 32 chars)
	req.Token = strings.TrimSpace(req.Token)
	if len(req.Token) != 32 {
		http.Error(w, "Invalid reset token format", http.StatusBadRequest)
		return
	}

	// Validate password
	if err := validatePassword(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Find user with matching reset token
	user, err := h.userRepo.GetUserByResetToken(r.Context(), req.Token)
	if err != nil {
		http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
		return
	}

	// Enforce reset token expiry
	if user.ResetTokenExpiry.IsZero() || time.Now().After(user.ResetTokenExpiry) {
		http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
		return
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	// Update user's password and clear reset token
	user.Password = string(hashedPassword)
	user.ResetToken = "" // Clear the reset token after use
	user.ResetTokenExpiry = time.Time{}

	if err := h.userRepo.UpdateUser(r.Context(), user); err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Password has been reset successfully"))
}

// Profile handles user profile operations
func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	// Get user email from JWT token
	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	email, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Get user from database
	user, err := h.userRepo.GetUserByEmail(r.Context(), email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusNotFound)
		return
	}

	// Handle different HTTP methods
	switch r.Method {
	case http.MethodGet:
		// Return user profile data
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":    user.Email,
			"alias":    user.Alias,
			"verified": user.Verified,
		})
	case http.MethodPut:
		// Update user profile
		var updateData struct {
			CurrentPassword string `json:"currentPassword"`
			NewPassword     string `json:"newPassword,omitempty"`
			Alias           string `json:"alias,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate alias length if provided
		if updateData.Alias != "" {
			updateData.Alias = strings.TrimSpace(updateData.Alias)
			if utf8.RuneCountInString(updateData.Alias) > 100 {
				http.Error(w, "Alias must be 100 characters or less", http.StatusBadRequest)
				return
			}
			if !utf8.ValidString(updateData.Alias) {
				http.Error(w, "Alias contains invalid characters", http.StatusBadRequest)
				return
			}
		}

		// Validate new password if provided
		if updateData.NewPassword != "" {
			if err := validatePassword(updateData.NewPassword); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		// Verify current password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(updateData.CurrentPassword))
		if err != nil {
			// Don't reveal which field is wrong
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// If new password is provided, update it
		if updateData.NewPassword != "" {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateData.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				http.Error(w, "Error updating password", http.StatusInternalServerError)
				return
			}
			user.Password = string(hashedPassword)
		}

		// If alias is provided, update it
		if updateData.Alias != "" {
			user.Alias = updateData.Alias
		}

		// Save updated user
		err = h.userRepo.UpdateUser(r.Context(), user)
		if err != nil {
			http.Error(w, "Error updating profile", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Profile updated successfully",
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// SetupAuthRoutes configures the base authentication routes
func (h *AuthHandler) SetupAuthRoutes(r chi.Router) {
	// Public routes
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, Chi Router!")
	})

	// Login route
	r.Post("/login", h.Login)

	// Email verification route
	r.Post("/verify-email", h.VerifyEmail)

	// Mount protected routes
	r.Group(func(r chi.Router) {
		// Seek, verify and validate JWT tokens
		r.Use(jwtauth.Verifier(h.tokenAuth))
		r.Use(jwtauth.Authenticator(h.tokenAuth))

		// Mount the protected routes router
		r.Mount("/", h.router)
	})
}

// RegisterProtectedRoute registers a new protected route
func (h *AuthHandler) RegisterProtectedRoute(method, pattern string, handler http.HandlerFunc) {
	h.router.Method(method, pattern, handler)
}

// RegisterProtectedRoutes registers multiple protected routes
type RouteHandler struct {
	Method  string
	Pattern string
	Handler http.HandlerFunc
}

// RegisterProtectedRoutes registers multiple protected routes at once
func (h *AuthHandler) RegisterProtectedRoutes(routes []RouteHandler) {
	for _, route := range routes {
		h.router.Method(route.Method, route.Pattern, route.Handler)
	}
}
