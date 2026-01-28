package internal

import (
	"antosara-auth/pkg"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthHandler handles authentication related operations
type AuthHandler struct {
	tokenAuth        *jwtauth.JWTAuth
	userRepo         pkg.UserRepository
	tokenRevokeRepo  pkg.TokenRevocationRepository
	router           chi.Router
	mu               sync.RWMutex
}

// NewAuthHandler creates a new AuthHandler instance
func NewAuthHandler(secretKey string, userRepo pkg.UserRepository, tokenRevokeRepo pkg.TokenRevocationRepository) *AuthHandler {
	return &AuthHandler{
		tokenAuth:       jwtauth.New("HS256", []byte(secretKey), nil),
		userRepo:        userRepo,
		tokenRevokeRepo: tokenRevokeRepo,
		router:          chi.NewRouter(),
	}
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

	// Determine if we should use Secure flag (use Secure in production)
	secure := os.Getenv("MODE") != "DEV"

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		MaxAge:   expiryHours * 3600, // Convert hours to seconds
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearAuthCookie clears the authentication cookie
func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   os.Getenv("MODE") != "DEV",
		SameSite: http.SameSiteStrictMode,
	})
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
			// On error, allow the request to proceed (fail open for availability)
			// In production, you might want to fail closed for security
			next.ServeHTTP(w, r)
			return
		}

		if revoked {
			http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CreateJWTToken creates a new JWT token with enhanced security claims
func CreateJWTToken(email string) (string, error) {
	// Get secret key from environment
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		return "", fmt.Errorf("SECRET_KEY environment variable not set")
	}

	// Get expiry hours from environment
	expiryHours := 24 // Default to 24 hours if not set
	if expiryStr := os.Getenv("JWT_EXPIRY_HOURS"); expiryStr != "" {
		if hours, err := strconv.Atoi(expiryStr); err == nil && hours > 0 {
			expiryHours = hours
		}
	}

	// Create new JWT auth with secret key
	tokenAuth := jwtauth.New("HS256", []byte(secretKey), nil)

	// Current time
	now := time.Now()

	// Generate JWT token with enhanced security claims
	_, tokenString, err := tokenAuth.Encode(map[string]interface{}{
		// Standard claims
		"sub": email,                                                  // Subject (user identifier)
		"iat": now.Unix(),                                             // Issued At
		"exp": now.Add(time.Duration(expiryHours) * time.Hour).Unix(), // Expiration Time
		"nbf": now.Unix(),                                             // Not Before
		"jti": uuid.New().String(),                                    // JWT ID (unique identifier for the token)

		// Custom claims
		"email": email,      // User's email
		"iss":   "antosara", // Issuer
		"aud":   email,      // Audience (specific to the user)
		"type":  "access",   // Token type
	})

	if err != nil {
		return "", fmt.Errorf("failed to create JWT token: %v", err)
	}

	return tokenString, nil
}

// validatePassword checks password complexity
func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
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

	// Check for account lockout
	if err := h.checkAccountLockout(loginData.Email); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	// Get user from database
	user, err := h.userRepo.GetUserByEmail(r.Context(), loginData.Email)
	if err != nil {
		if err := h.recordFailedAttempt(loginData.Email); err != nil {
			log.Printf("Failed to record failed attempt: %v", err)
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Check if email is verified
	if !user.Verified {
		http.Error(w, "Email not verified", http.StatusUnauthorized)
		return
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		if err := h.recordFailedAttempt(loginData.Email); err != nil {
			log.Printf("Failed to record failed attempt: %v", err)
		}
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Clear failed attempts on successful login
	if err := h.clearFailedAttempts(loginData.Email); err != nil {
		log.Printf("Failed to clear failed attempts: %v", err)
	}

	// Generate JWT token
	tokenString, err := CreateJWTToken(user.Email)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	// Set secure httpOnly cookie with the token
	setAuthCookie(w, tokenString)

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
			http.Error(w, "Email already exists", http.StatusBadRequest)
			return
		}

		// User exists but not verified - update verification code and resend email
		verificationCode := fmt.Sprintf("%06d", rand.Intn(1000000))
		existingUser.VerificationCode = verificationCode

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
	user := &pkg.User{
		Email:            signupData.Email,
		Password:         string(hashedPassword),
		VerificationCode: fmt.Sprintf("%06d", rand.Intn(1000000)),
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
		http.Error(w, "Email already verified", http.StatusBadRequest)
		return
	}

	// Verify the code
	if user.VerificationCode != verifyData.VerificationCode {
		http.Error(w, "Invalid verification code", http.StatusBadRequest)
		return
	}

	// Update user verification status
	user.Verified = true
	user.VerificationCode = "" // Clear the verification code

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
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
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

	// Check if user exists
	user, err := h.userRepo.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Don't reveal if user exists or not
		http.Error(w, "If your email is registered, you will receive a password reset link", http.StatusOK)
		return
	}

	// Generate a random reset token
	resetToken := generateRandomString(32)
	user.ResetToken = resetToken

	// Update user with reset token
	if err := h.userRepo.UpdateUser(r.Context(), user); err != nil {
		http.Error(w, "Failed to process reset request", http.StatusInternalServerError)
		return
	}

	// Send password reset email
	go func(email, token string) {
		if err := sendPasswordResetEmail(email, token); err != nil {
			log.Printf("Failed to send password reset email to %s: %v", email, err)
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

	// Find user with matching reset token
	user, err := h.userRepo.GetUserByResetToken(r.Context(), req.Token)
	if err != nil {
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

		// Verify current password
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(updateData.CurrentPassword))
		if err != nil {
			http.Error(w, "Invalid current password", http.StatusUnauthorized)
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
