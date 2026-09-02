// Integration tests for the Postgres-compatible backend (PostgreSQL or CockroachDB).
// Tests are skipped unless POSTGRES_TEST_DSN is set.
//
// Docker PostgreSQL:
//
//	docker run -d --name antosara-pg-test \
//	  -e POSTGRES_PASSWORD=postgres \
//	  -e POSTGRES_DB=antosara_auth_test \
//	  -p 5433:5432 postgres:16-alpine
//	POSTGRES_TEST_DSN='postgres://postgres:postgres@localhost:5433/antosara_auth_test?sslmode=disable' \
//	  go test ./internal/... -run Postgres -v
//	docker rm -f antosara-pg-test
//
// Local CockroachDB (secure, single-node with certs):
//
//	cockroach sql --certs-dir=certs -e "CREATE DATABASE IF NOT EXISTS antosara_auth_test;"
//	POSTGRES_TEST_DSN='postgres://root@localhost:26257/antosara_auth_test?sslmode=verify-full&sslrootcert=/path/to/certs/ca.crt&sslcert=/path/to/certs/client.root.crt&sslkey=/path/to/certs/client.root.key' \
//	  go test ./internal/... -run Postgres -v
//
// Insecure local CockroachDB:
//
//	POSTGRES_TEST_DSN='postgres://root@localhost:26257/defaultdb?sslmode=disable' go test ./internal/... -run Postgres -v
package internal

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/antosara-dev/antosara-auth/pkg"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func setupPostgresRepos(t *testing.T) (pkg.UserRepository, pkg.TokenRevocationRepository, pkg.SessionCSRFRepository) {
	t.Helper()

	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set; skipping postgres integration tests")
	}

	userRepo, tokenRepo, csrfRepo, err := NewPostgresRepositories(dsn)
	require.NoError(t, err)

	t.Cleanup(func() {
		if db, ok := userRepo.(*PostgresUserRepository); ok {
			_ = db.db.Close()
		}
	})

	return userRepo, tokenRepo, csrfRepo
}

func uniqueEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test-%s@example.com", uuid.NewString())
}

func TestPostgresUserRepository(t *testing.T) {
	userRepo, _, _ := setupPostgresRepos(t)
	ctx := context.Background()

	t.Run("CreateGetUpdateDelete", func(t *testing.T) {
		email := uniqueEmail(t)
		user := &pkg.User{
			Email:    email,
			Alias:    "alice",
			Password: "hashed-password",
		}

		require.NoError(t, userRepo.CreateUser(ctx, user))
		require.False(t, user.Verified)
		require.Len(t, user.VerificationCode, 6)
		require.True(t, user.VerificationCodeExpiry.After(time.Now()))

		got, err := userRepo.GetUserByEmail(ctx, email)
		require.NoError(t, err)
		require.Equal(t, email, got.Email)
		require.Equal(t, "alice", got.Alias)
		require.Equal(t, "hashed-password", got.Password)
		require.False(t, got.Verified)
		require.Equal(t, user.VerificationCode, got.VerificationCode)

		got.Verified = true
		got.Alias = "alice-updated"
		got.Password = "new-hash"
		got.ResetToken = "reset-token-123"
		got.ResetTokenExpiry = time.Now().Add(time.Hour)
		got.FailedAttempts = 2
		got.LockoutUntil = time.Now().Add(30 * time.Minute)
		require.NoError(t, userRepo.UpdateUser(ctx, got))

		updated, err := userRepo.GetUserByEmail(ctx, email)
		require.NoError(t, err)
		require.True(t, updated.Verified)
		require.Equal(t, "alice-updated", updated.Alias)
		require.Equal(t, "reset-token-123", updated.ResetToken)
		require.Equal(t, 2, updated.FailedAttempts)

		got.ResetToken = ""
		got.ResetTokenExpiry = time.Time{}
		require.NoError(t, userRepo.UpdateUser(ctx, got))

		cleared, err := userRepo.GetUserByEmail(ctx, email)
		require.NoError(t, err)
		require.Empty(t, cleared.ResetToken)
		require.True(t, cleared.ResetTokenExpiry.IsZero())

		require.NoError(t, userRepo.DeleteUser(ctx, email))

		_, err = userRepo.GetUserByEmail(ctx, email)
		require.ErrorIs(t, err, pkg.ErrUserNotFound)
	})

	t.Run("CreateUserDuplicate", func(t *testing.T) {
		email := uniqueEmail(t)
		user := &pkg.User{Email: email, Alias: "bob", Password: "hash"}

		require.NoError(t, userRepo.CreateUser(ctx, user))

		dup := &pkg.User{Email: email, Alias: "other", Password: "other-hash"}
		err := userRepo.CreateUser(ctx, dup)
		require.Error(t, err)
		require.EqualError(t, err, "user already exists")

		require.NoError(t, userRepo.DeleteUser(ctx, email))
	})

	t.Run("GetUserByEmailNotFound", func(t *testing.T) {
		_, err := userRepo.GetUserByEmail(ctx, uniqueEmail(t))
		require.ErrorIs(t, err, pkg.ErrUserNotFound)
	})

	t.Run("GetUserByResetToken", func(t *testing.T) {
		email := uniqueEmail(t)
		token := "reset-" + uuid.NewString()
		user := &pkg.User{
			Email:            email,
			Alias:            "carol",
			Password:         "hash",
			ResetToken:       token,
			ResetTokenExpiry: time.Now().Add(time.Hour),
		}
		require.NoError(t, userRepo.CreateUser(ctx, user))

		got, err := userRepo.GetUserByResetToken(ctx, token)
		require.NoError(t, err)
		require.Equal(t, email, got.Email)

		_, err = userRepo.GetUserByResetToken(ctx, "missing-token")
		require.ErrorIs(t, err, pkg.ErrUserNotFound)

		require.NoError(t, userRepo.DeleteUser(ctx, email))
	})

	t.Run("UpdateUserNotFound", func(t *testing.T) {
		err := userRepo.UpdateUser(ctx, &pkg.User{
			Email:    uniqueEmail(t),
			Alias:    "ghost",
			Password: "hash",
		})
		require.ErrorIs(t, err, pkg.ErrUserNotFound)
	})

	t.Run("DeleteUserNotFound", func(t *testing.T) {
		err := userRepo.DeleteUser(ctx, uniqueEmail(t))
		require.ErrorIs(t, err, pkg.ErrUserNotFound)
	})
}

func TestPostgresTokenRevocationRepository(t *testing.T) {
	_, tokenRepo, _ := setupPostgresRepos(t)
	ctx := context.Background()

	t.Run("RevokeAndCheck", func(t *testing.T) {
		jti := "jti-" + uuid.NewString()
		expiresAt := time.Now().Add(time.Hour)

		require.NoError(t, tokenRepo.RevokeToken(ctx, jti, expiresAt))

		revoked, err := tokenRepo.IsTokenRevoked(ctx, jti)
		require.NoError(t, err)
		require.True(t, revoked)

		// Upsert same jti with a new expiry.
		newExpiry := time.Now().Add(2 * time.Hour)
		require.NoError(t, tokenRepo.RevokeToken(ctx, jti, newExpiry))

		revoked, err = tokenRepo.IsTokenRevoked(ctx, jti)
		require.NoError(t, err)
		require.True(t, revoked)
	})

	t.Run("ExpiredTokenNotRevoked", func(t *testing.T) {
		jti := "jti-expired-" + uuid.NewString()
		require.NoError(t, tokenRepo.RevokeToken(ctx, jti, time.Now().Add(-time.Minute)))

		revoked, err := tokenRepo.IsTokenRevoked(ctx, jti)
		require.NoError(t, err)
		require.False(t, revoked)
	})

	t.Run("NotRevoked", func(t *testing.T) {
		revoked, err := tokenRepo.IsTokenRevoked(ctx, "jti-missing-"+uuid.NewString())
		require.NoError(t, err)
		require.False(t, revoked)
	})
}

func TestPostgresSessionCSRFRepository(t *testing.T) {
	_, _, csrfRepo := setupPostgresRepos(t)
	ctx := context.Background()

	t.Run("PutGetDelete", func(t *testing.T) {
		jti := "csrf-" + uuid.NewString()
		token := "csrf-token-" + uuid.NewString()
		expiresAt := time.Now().Add(time.Hour)

		require.NoError(t, csrfRepo.Put(ctx, jti, token, expiresAt))

		got, err := csrfRepo.Get(ctx, jti)
		require.NoError(t, err)
		require.Equal(t, jti, got.JTI)
		require.Equal(t, token, got.Token)
		require.WithinDuration(t, expiresAt, got.ExpiresAt, time.Second)

		newToken := "csrf-token-updated"
		newExpiry := time.Now().Add(2 * time.Hour)
		require.NoError(t, csrfRepo.Put(ctx, jti, newToken, newExpiry))

		got, err = csrfRepo.Get(ctx, jti)
		require.NoError(t, err)
		require.Equal(t, newToken, got.Token)

		require.NoError(t, csrfRepo.Delete(ctx, jti))

		_, err = csrfRepo.Get(ctx, jti)
		require.ErrorIs(t, err, pkg.ErrUserNotFound)
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		jti := "csrf-expired-" + uuid.NewString()
		require.NoError(t, csrfRepo.Put(ctx, jti, "expired-token", time.Now().Add(-time.Minute)))

		_, err := csrfRepo.Get(ctx, jti)
		require.ErrorIs(t, err, pkg.ErrUserNotFound)
	})

	t.Run("GetNotFound", func(t *testing.T) {
		_, err := csrfRepo.Get(ctx, "csrf-missing-"+uuid.NewString())
		require.ErrorIs(t, err, pkg.ErrUserNotFound)
	})
}
