package pkg

import (
	"context"
	"errors"
	"time"
)

// User represents a user in the system
type User struct {
	Email                  string    `json:"email"`
	Alias                  string    `json:"alias"`
	Password               string    `json:"-"` // In production, this should be hashed
	Verified               bool      `json:"verified"`
	VerificationCode       string    `json:"-"`
	VerificationCodeExpiry time.Time `json:"-"`
	ResetToken             string    `json:"-"`
	ResetTokenExpiry       time.Time `json:"-"`
	FailedAttempts         int       `json:"-"`
	LockoutUntil           time.Time `json:"-"`
}

// UserRepository defines the interface for user data operations
type UserRepository interface {
	// GetUserByEmail retrieves a user by their email
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// CreateUser creates a new user
	CreateUser(ctx context.Context, user *User) error

	// UpdateUser updates an existing user
	UpdateUser(ctx context.Context, user *User) error

	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, email string) error

	// GetUserByResetToken retrieves a user by their reset token
	GetUserByResetToken(ctx context.Context, token string) (*User, error)
}

// RevokedToken represents a revoked JWT token
type RevokedToken struct {
	JTI       string    `json:"jti"`       // JWT ID (unique identifier for the token)
	RevokedAt time.Time `json:"revokedAt"` // When the token was revoked
	ExpiresAt time.Time `json:"expiresAt"` // When the token expires (for cleanup)
}

// TokenRevocationRepository defines the interface for token revocation operations
type TokenRevocationRepository interface {
	// RevokeToken marks a token as revoked
	RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error

	// IsTokenRevoked checks if a token is revoked
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)

	// CleanupExpiredRevocations removes expired token revocations
	CleanupExpiredRevocations(ctx context.Context) error
}

// SessionCSRF represents the current CSRF token for a session (JWT jti).
type SessionCSRF struct {
	JTI       string    `json:"jti"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// SessionCSRFRepository stores session-bound CSRF tokens.
type SessionCSRFRepository interface {
	Put(ctx context.Context, jti string, token string, expiresAt time.Time) error
	Get(ctx context.Context, jti string) (*SessionCSRF, error)
	Delete(ctx context.Context, jti string) error
}

// Common errors
var (
	ErrUserNotFound       = errors.New("invalid credentials")
	ErrInvalidCredentials = errors.New("invalid credentials")
)
