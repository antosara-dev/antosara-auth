package internal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/antosara-dev/antosara-auth/pkg"

	"modernc.org/sqlite"
)

const (
	sqliteUsersTable         = "users"
	sqliteRevokedTokensTable = "revoked_tokens"
	sqliteSessionCSRFTable   = "session_csrf"

	sqliteConstraint           = 19
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintUnique     = 2067
)

// SQLiteUserRepository implements pkg.UserRepository using SQLite.
type SQLiteUserRepository struct {
	db *sql.DB
}

// SQLiteTokenRevocationRepository implements pkg.TokenRevocationRepository using SQLite.
type SQLiteTokenRevocationRepository struct {
	db *sql.DB
}

// SQLiteSessionCSRFRepository implements pkg.SessionCSRFRepository using SQLite.
type SQLiteSessionCSRFRepository struct {
	db *sql.DB
}

// NewSQLiteRepositories opens a SQLite connection, ensures schema exists,
// and returns all three repository implementations sharing the same pool.
func NewSQLiteRepositories(dsn string) (pkg.UserRepository, pkg.TokenRevocationRepository, pkg.SessionCSRFRepository, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, nil, nil, fmt.Errorf("sqlite dsn is required")
	}

	if err := ensureSQLiteDir(dsn); err != nil {
		return nil, nil, nil, err
	}

	db, err := sql.Open("sqlite", normalizeSQLiteDSN(dsn))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open sqlite connection: %w", err)
	}

	// Serialize access: SQLite allows one writer at a time.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, nil, nil, fmt.Errorf("failed to ping sqlite: %w", err)
	}

	if err := ensureSQLiteSchema(db); err != nil {
		_ = db.Close()
		return nil, nil, nil, err
	}

	userRepo := &SQLiteUserRepository{db: db}
	tokenRepo := &SQLiteTokenRevocationRepository{db: db}
	csrfRepo := &SQLiteSessionCSRFRepository{db: db}

	return userRepo, tokenRepo, csrfRepo, nil
}

func normalizeSQLiteDSN(dsn string) string {
	if dsn == ":memory:" || strings.HasPrefix(dsn, "file::memory:") {
		return dsn
	}
	if strings.Contains(dsn, "?") {
		return dsn
	}

	uri := dsn
	if !strings.HasPrefix(dsn, "file:") {
		uri = "file:" + dsn
	}

	return uri + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
}

func sqliteFilePath(dsn string) string {
	s := strings.TrimSpace(dsn)
	if s == "" || s == ":memory:" || strings.HasPrefix(s, "file::memory:") {
		return ""
	}

	s = strings.TrimPrefix(s, "file://")
	s = strings.TrimPrefix(s, "file:")
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[:i]
	}

	return s
}

func ensureSQLiteDir(dsn string) error {
	path := sqliteFilePath(dsn)
	if path == "" {
		return nil
	}

	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create sqlite directory: %w", err)
	}

	return nil
}

func ensureSQLiteSchema(db *sql.DB) error {
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			email TEXT PRIMARY KEY,
			alias TEXT NOT NULL DEFAULT '',
			password TEXT NOT NULL,
			verified INTEGER NOT NULL DEFAULT 0,
			verification_code TEXT NOT NULL DEFAULT '',
			verification_code_expiry TEXT,
			reset_token TEXT,
			reset_token_expiry TEXT,
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			lockout_until TEXT
		)`, sqliteUsersTable),
		fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS users_reset_token_idx ON %s (reset_token)
			WHERE reset_token IS NOT NULL AND reset_token <> ''`, sqliteUsersTable),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			jti TEXT PRIMARY KEY,
			revoked_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`, sqliteRevokedTokensTable),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			jti TEXT PRIMARY KEY,
			token TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`, sqliteSessionCSRFTable),
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to ensure sqlite schema: %w", err)
		}
	}

	return nil
}

func isSQLiteUniqueConstraint(err error) bool {
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		switch sqliteErr.Code() {
		case sqliteConstraintPrimaryKey, sqliteConstraintUnique:
			return true
		case sqliteConstraint:
			msg := strings.ToLower(sqliteErr.Error())
			return strings.Contains(msg, "unique") || strings.Contains(msg, "primary key")
		}
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") ||
		strings.Contains(msg, "primary key constraint failed")
}

// sqliteTime stores timestamps as RFC3339Nano TEXT. modernc.org/sqlite does not
// scan TEXT back into time.Time, so we format/parse explicitly.
func sqliteTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseSQLiteTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid sqlite time %q: %w", raw, err)
	}
	return t, nil
}

func parseSQLiteNullTime(ns sql.NullString) (time.Time, error) {
	if !ns.Valid {
		return time.Time{}, nil
	}
	return parseSQLiteTime(ns.String)
}

func scanSQLiteUser(row *sql.Row) (*pkg.User, error) {
	var user pkg.User
	var verificationCodeExpiry, resetTokenExpiry, lockoutUntil sql.NullString
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

	user.VerificationCodeExpiry, err = parseSQLiteNullTime(verificationCodeExpiry)
	if err != nil {
		return nil, err
	}
	if resetToken.Valid {
		user.ResetToken = resetToken.String
	}
	user.ResetTokenExpiry, err = parseSQLiteNullTime(resetTokenExpiry)
	if err != nil {
		return nil, err
	}
	user.LockoutUntil, err = parseSQLiteNullTime(lockoutUntil)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *SQLiteUserRepository) GetUserByEmail(ctx context.Context, email string) (*pkg.User, error) {
	row := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT email, alias, password, verified, verification_code, verification_code_expiry,
		       reset_token, reset_token_expiry, failed_attempts, lockout_until
		FROM %s WHERE email = ?`, sqliteUsersTable), email)

	user, err := scanSQLiteUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (r *SQLiteUserRepository) CreateUser(ctx context.Context, user *pkg.User) error {
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

	resetToken := nullableString(user.ResetToken)
	resetTokenExpiry := sqliteTime(user.ResetTokenExpiry)
	lockoutUntil := sqliteTime(user.LockoutUntil)

	_, err = r.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (
			email, alias, password, verified, verification_code, verification_code_expiry,
			reset_token, reset_token_expiry, failed_attempts, lockout_until
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, sqliteUsersTable),
		user.Email,
		user.Alias,
		user.Password,
		user.Verified,
		user.VerificationCode,
		sqliteTime(user.VerificationCodeExpiry),
		resetToken,
		resetTokenExpiry,
		user.FailedAttempts,
		lockoutUntil,
	)
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return fmt.Errorf("user already exists")
		}
		return fmt.Errorf("failed to create user: %v", err)
	}

	go func(email, code string) {
		_ = sendVerificationEmail(email, code)
	}(user.Email, user.VerificationCode)

	return nil
}

func (r *SQLiteUserRepository) UpdateUser(ctx context.Context, user *pkg.User) error {
	resetToken := nullableString(user.ResetToken)
	resetTokenExpiry := sqliteTime(user.ResetTokenExpiry)
	lockoutUntil := sqliteTime(user.LockoutUntil)
	verificationCodeExpiry := sqliteTime(user.VerificationCodeExpiry)

	result, err := r.db.ExecContext(ctx, fmt.Sprintf(`
		UPDATE %s SET
			alias = ?,
			password = ?,
			verified = ?,
			verification_code = ?,
			verification_code_expiry = ?,
			reset_token = ?,
			reset_token_expiry = ?,
			failed_attempts = ?,
			lockout_until = ?
		WHERE email = ?`, sqliteUsersTable),
		user.Alias,
		user.Password,
		user.Verified,
		user.VerificationCode,
		verificationCodeExpiry,
		resetToken,
		resetTokenExpiry,
		user.FailedAttempts,
		lockoutUntil,
		user.Email,
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

func (r *SQLiteUserRepository) DeleteUser(ctx context.Context, email string) error {
	result, err := r.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE email = ?`, sqliteUsersTable), email)
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

func (r *SQLiteUserRepository) GetUserByResetToken(ctx context.Context, token string) (*pkg.User, error) {
	row := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT email, alias, password, verified, verification_code, verification_code_expiry,
		       reset_token, reset_token_expiry, failed_attempts, lockout_until
		FROM %s WHERE reset_token = ?`, sqliteUsersTable), token)

	user, err := scanSQLiteUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to query user by reset token: %v", err)
	}

	return user, nil
}

func (r *SQLiteTokenRevocationRepository) RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (jti, revoked_at, expires_at)
		VALUES (?, ?, ?)
		ON CONFLICT (jti) DO UPDATE SET revoked_at = excluded.revoked_at, expires_at = excluded.expires_at`,
		sqliteRevokedTokensTable),
		jti,
		sqliteTime(time.Now()),
		sqliteTime(expiresAt),
	)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %v", err)
	}

	return nil
}

func (r *SQLiteTokenRevocationRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	var expiresRaw string
	err := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT expires_at FROM %s WHERE jti = ?`, sqliteRevokedTokensTable), jti).Scan(&expiresRaw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check token revocation: %v", err)
	}

	expiresAt, err := parseSQLiteTime(expiresRaw)
	if err != nil {
		return false, fmt.Errorf("failed to check token revocation: %v", err)
	}

	if time.Now().After(expiresAt) {
		return false, nil
	}

	return true, nil
}

func (r *SQLiteSessionCSRFRepository) Put(ctx context.Context, jti string, token string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (jti, token, expires_at)
		VALUES (?, ?, ?)
		ON CONFLICT (jti) DO UPDATE SET token = excluded.token, expires_at = excluded.expires_at`,
		sqliteSessionCSRFTable),
		jti,
		token,
		sqliteTime(expiresAt),
	)
	if err != nil {
		return fmt.Errorf("failed to store session csrf: %v", err)
	}

	return nil
}

func (r *SQLiteSessionCSRFRepository) Get(ctx context.Context, jti string) (*pkg.SessionCSRF, error) {
	var out pkg.SessionCSRF
	var expiresRaw string
	err := r.db.QueryRowContext(ctx, fmt.Sprintf(`
		SELECT jti, token, expires_at FROM %s WHERE jti = ?`, sqliteSessionCSRFTable), jti).
		Scan(&out.JTI, &out.Token, &expiresRaw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, pkg.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get session csrf: %v", err)
	}

	expiresAt, err := parseSQLiteTime(expiresRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to get session csrf: %v", err)
	}
	out.ExpiresAt = expiresAt

	if time.Now().After(out.ExpiresAt) {
		return nil, pkg.ErrUserNotFound
	}

	return &out, nil
}

func (r *SQLiteSessionCSRFRepository) Delete(ctx context.Context, jti string) error {
	_, err := r.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE jti = ?`, sqliteSessionCSRFTable), jti)
	if err != nil {
		return fmt.Errorf("failed to delete session csrf: %v", err)
	}

	return nil
}
