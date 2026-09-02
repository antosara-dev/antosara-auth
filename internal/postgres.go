package internal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/antosara-dev/antosara-auth/pkg"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	postgresUsersTable         = "users"
	postgresRevokedTokensTable = "revoked_tokens"
	postgresSessionCSRFTable   = "session_csrf"
)

// PostgresUserRepository implements pkg.UserRepository using PostgreSQL.
type PostgresUserRepository struct {
	db *sql.DB
}

// PostgresTokenRevocationRepository implements pkg.TokenRevocationRepository using PostgreSQL.
type PostgresTokenRevocationRepository struct {
	db *sql.DB
}

// PostgresSessionCSRFRepository implements pkg.SessionCSRFRepository using PostgreSQL.
type PostgresSessionCSRFRepository struct {
	db *sql.DB
}

// NewPostgresRepositories opens a PostgreSQL connection, ensures schema exists,
// and returns all three repository implementations sharing the same pool.
func NewPostgresRepositories(dsn string) (pkg.UserRepository, pkg.TokenRevocationRepository, pkg.SessionCSRFRepository, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, nil, nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	if err := ensurePostgresSchema(db); err != nil {
		_ = db.Close()
		return nil, nil, nil, err
	}

	userRepo := &PostgresUserRepository{db: db}
	tokenRepo := &PostgresTokenRevocationRepository{db: db}
	csrfRepo := &PostgresSessionCSRFRepository{db: db}

	return userRepo, tokenRepo, csrfRepo, nil
}

func ensurePostgresSchema(db *sql.DB) error {
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			email TEXT PRIMARY KEY,
			alias TEXT NOT NULL DEFAULT '',
			password TEXT NOT NULL,
			verified BOOLEAN NOT NULL DEFAULT false,
			verification_code TEXT NOT NULL DEFAULT '',
			verification_code_expiry TIMESTAMPTZ,
			reset_token TEXT,
			reset_token_expiry TIMESTAMPTZ,
			failed_attempts INT NOT NULL DEFAULT 0,
			lockout_until TIMESTAMPTZ
		)`, postgresUsersTable),
		fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS users_reset_token_idx ON %s (reset_token)
			WHERE reset_token IS NOT NULL AND reset_token <> ''`, postgresUsersTable),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			jti TEXT PRIMARY KEY,
			revoked_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL
		)`, postgresRevokedTokensTable),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			jti TEXT PRIMARY KEY,
			token TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL
		)`, postgresSessionCSRFTable),
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to ensure postgres schema: %w", err)
		}
	}

	return nil
}

func (r *PostgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*pkg.User, error) {
	row := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT email, alias, password, verified, verification_code, verification_code_expiry,
		       reset_token, reset_token_expiry, failed_attempts, lockout_until
		FROM %s WHERE email = $1`, postgresUsersTable), email)

	user, err := scanSQLUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (r *PostgresUserRepository) CreateUser(ctx context.Context, user *pkg.User) error {
	user.Verified = false

	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return fmt.Errorf("failed to generate verification code: %v", err)
	}
	user.VerificationCode = fmt.Sprintf("%06d", n.Int64())

	expiryMinutes := 24 * 60
	if s := os.Getenv("VERIFICATION_CODE_EXPIRY_MINUTES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			expiryMinutes = v
		}
	}
	user.VerificationCodeExpiry = time.Now().Add(time.Duration(expiryMinutes) * time.Minute)

	resetToken, resetTokenExpiry := nullableString(user.ResetToken), nullableTime(user.ResetTokenExpiry)
	lockoutUntil := nullableTime(user.LockoutUntil)

	_, err = r.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (
			email, alias, password, verified, verification_code, verification_code_expiry,
			reset_token, reset_token_expiry, failed_attempts, lockout_until
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, postgresUsersTable),
		user.Email,
		user.Alias,
		user.Password,
		user.Verified,
		user.VerificationCode,
		user.VerificationCodeExpiry,
		resetToken,
		resetTokenExpiry,
		user.FailedAttempts,
		lockoutUntil,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("user already exists")
		}
		return fmt.Errorf("failed to create user: %v", err)
	}

	go func(email, code string) {
		_ = sendVerificationEmail(email, code)
	}(user.Email, user.VerificationCode)

	return nil
}

func (r *PostgresUserRepository) UpdateUser(ctx context.Context, user *pkg.User) error {
	resetToken, resetTokenExpiry := nullableString(user.ResetToken), nullableTime(user.ResetTokenExpiry)
	lockoutUntil := nullableTime(user.LockoutUntil)
	verificationCodeExpiry := nullableTime(user.VerificationCodeExpiry)

	result, err := r.db.ExecContext(ctx, fmt.Sprintf(`
		UPDATE %s SET
			alias = $2,
			password = $3,
			verified = $4,
			verification_code = $5,
			verification_code_expiry = $6,
			reset_token = $7,
			reset_token_expiry = $8,
			failed_attempts = $9,
			lockout_until = $10
		WHERE email = $1`, postgresUsersTable),
		user.Email,
		user.Alias,
		user.Password,
		user.Verified,
		user.VerificationCode,
		verificationCodeExpiry,
		resetToken,
		resetTokenExpiry,
		user.FailedAttempts,
		lockoutUntil,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}
	if rows == 0 {
		return pkg.ErrUserNotFound
	}

	return nil
}

func (r *PostgresUserRepository) DeleteUser(ctx context.Context, email string) error {
	result, err := r.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE email = $1`, postgresUsersTable), email)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}
	if rows == 0 {
		return pkg.ErrUserNotFound
	}

	return nil
}

func (r *PostgresUserRepository) GetUserByResetToken(ctx context.Context, token string) (*pkg.User, error) {
	row := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT email, alias, password, verified, verification_code, verification_code_expiry,
		       reset_token, reset_token_expiry, failed_attempts, lockout_until
		FROM %s WHERE reset_token = $1`, postgresUsersTable), token)

	user, err := scanSQLUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to query user by reset token: %v", err)
	}

	return user, nil
}

func (r *PostgresTokenRevocationRepository) RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (jti, revoked_at, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti) DO UPDATE SET revoked_at = EXCLUDED.revoked_at, expires_at = EXCLUDED.expires_at`,
		postgresRevokedTokensTable),
		jti,
		time.Now(),
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %v", err)
	}

	return nil
}

func (r *PostgresTokenRevocationRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	var expiresAt time.Time
	err := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT expires_at FROM %s WHERE jti = $1`, postgresRevokedTokensTable), jti).Scan(&expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check token revocation: %v", err)
	}

	if time.Now().After(expiresAt) {
		return false, nil
	}

	return true, nil
}

func (r *PostgresSessionCSRFRepository) Put(ctx context.Context, jti string, token string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (jti, token, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (jti) DO UPDATE SET token = EXCLUDED.token, expires_at = EXCLUDED.expires_at`,
		postgresSessionCSRFTable),
		jti,
		token,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store session csrf: %v", err)
	}

	return nil
}

func (r *PostgresSessionCSRFRepository) Get(ctx context.Context, jti string) (*pkg.SessionCSRF, error) {
	var out pkg.SessionCSRF
	err := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT jti, token, expires_at FROM %s WHERE jti = $1`, postgresSessionCSRFTable), jti).
		Scan(&out.JTI, &out.Token, &out.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get session csrf: %v", err)
	}

	if time.Now().After(out.ExpiresAt) {
		return nil, pkg.ErrUserNotFound
	}

	return &out, nil
}

func (r *PostgresSessionCSRFRepository) Delete(ctx context.Context, jti string) error {
	_, err := r.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE jti = $1`, postgresSessionCSRFTable), jti)
	if err != nil {
		return fmt.Errorf("failed to delete session csrf: %v", err)
	}

	return nil
}

func scanSQLUser(row *sql.Row) (*pkg.User, error) {
	var user pkg.User
	var verificationCodeExpiry, resetTokenExpiry, lockoutUntil sql.NullTime
	var resetToken sql.NullString

	err := row.Scan(
		&user.Email,
		&user.Alias,
		&user.Password,
		&user.Verified,
		&user.VerificationCode,
		&verificationCodeExpiry,
		&resetToken,
		&resetTokenExpiry,
		&user.FailedAttempts,
		&lockoutUntil,
	)
	if err != nil {
		return nil, err
	}

	if verificationCodeExpiry.Valid {
		user.VerificationCodeExpiry = verificationCodeExpiry.Time
	}
	if resetToken.Valid {
		user.ResetToken = resetToken.String
	}
	if resetTokenExpiry.Valid {
		user.ResetTokenExpiry = resetTokenExpiry.Time
	}
	if lockoutUntil.Valid {
		user.LockoutUntil = lockoutUntil.Time
	}

	return &user, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
