package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const (
	sqlAuthCodesTable     = "oidc_auth_codes"
	sqlRefreshTokensTable = "oidc_refresh_tokens"
	sqlConsentsTable      = "oidc_consents"
)

// SQLStores implements CodeStore, RefreshStore, and ConsentStore on Postgres or SQLite.
type SQLStores struct {
	db     *sql.DB
	dollar bool
}

// NewSQLStores opens driver ("pgx" or "sqlite") with dsn and ensures OIDC tables exist.
func NewSQLStores(driver, dsn string) (*SQLStores, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, fmt.Errorf("oidc sql dsn is required")
	}
	if driver == "sqlite" {
		if err := ensureSQLiteDir(dsn); err != nil {
			return nil, err
		}
		dsn = normalizeSQLiteDSN(dsn)
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open oidc sql store: %w", err)
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(0)
	} else {
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(30 * time.Minute)
	}

	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping oidc sql store: %w", err)
	}

	s := &SQLStores{db: db, dollar: driver == "pgx"}
	if err := s.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLStores) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLStores) q(query string) string {
	if !s.dollar {
		return query
	}
	n := 0
	var b strings.Builder
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(fmt.Sprintf("%d", n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func (s *SQLStores) ensureSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS oidc_auth_codes (
			code_hash TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			nonce TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL,
			sub TEXT NOT NULL,
			session_jti TEXT NOT NULL DEFAULT '',
			auth_time BIGINT NOT NULL,
			expires_at BIGINT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
			token_hash TEXT PRIMARY KEY,
			family_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			sub TEXT NOT NULL,
			scope TEXT NOT NULL,
			session_jti TEXT NOT NULL DEFAULT '',
			auth_time BIGINT NOT NULL,
			expires_at BIGINT NOT NULL,
			consumed_at BIGINT
		)`,
		`CREATE INDEX IF NOT EXISTS oidc_refresh_family_idx ON oidc_refresh_tokens (family_id)`,
		`CREATE INDEX IF NOT EXISTS oidc_refresh_sub_idx ON oidc_refresh_tokens (sub)`,
		`CREATE TABLE IF NOT EXISTS oidc_consents (
			sub TEXT NOT NULL,
			client_id TEXT NOT NULL,
			scope TEXT NOT NULL,
			PRIMARY KEY (sub, client_id)
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure oidc sql schema: %w", err)
		}
	}
	return nil
}

func (s *SQLStores) Put(ctx context.Context, codeHash string, code AuthCode) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO oidc_auth_codes (
			code_hash, client_id, redirect_uri, code_challenge, nonce, scope, sub, session_jti, auth_time, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		codeHash, code.ClientID, code.RedirectURI, code.CodeChallenge, code.Nonce,
		code.Scope, code.Sub, code.SessionJTI, code.AuthTime.Unix(), code.ExpiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("store auth code: %w", err)
	}
	return nil
}

func (s *SQLStores) Consume(ctx context.Context, codeHash string) (*AuthCode, error) {
	row := s.db.QueryRowContext(ctx, s.q(`
		DELETE FROM oidc_auth_codes
		WHERE code_hash = ? AND expires_at > ?
		RETURNING client_id, redirect_uri, code_challenge, nonce, scope, sub, session_jti, auth_time, expires_at`),
		codeHash, time.Now().Unix(),
	)
	var code AuthCode
	var authUnix, expUnix int64
	err := row.Scan(
		&code.ClientID, &code.RedirectURI, &code.CodeChallenge, &code.Nonce,
		&code.Scope, &code.Sub, &code.SessionJTI, &authUnix, &expUnix,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("consume auth code: %w", err)
	}
	code.AuthTime = time.Unix(authUnix, 0)
	code.ExpiresAt = time.Unix(expUnix, 0)
	return &code, nil
}

func (s *SQLStores) PutRefresh(ctx context.Context, tokenHash string, rec RefreshRecord) error {
	return s.putRefresh(ctx, tokenHash, rec)
}

func (s *SQLStores) putRefresh(ctx context.Context, tokenHash string, rec RefreshRecord) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO oidc_refresh_tokens (
			token_hash, family_id, client_id, sub, scope, session_jti, auth_time, expires_at, consumed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`),
		tokenHash, rec.FamilyID, rec.ClientID, rec.Sub, rec.Scope, rec.SessionJTI,
		rec.AuthTime.Unix(), rec.ExpiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	return nil
}

func (s *SQLStores) ConsumeRefresh(ctx context.Context, tokenHash string) (*RefreshRecord, error) {
	return s.consumeRefresh(ctx, tokenHash)
}

func (s *SQLStores) consumeRefresh(ctx context.Context, tokenHash string) (*RefreshRecord, error) {
	var rec RefreshRecord
	var authUnix, expUnix int64
	var consumedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT family_id, client_id, sub, scope, session_jti, auth_time, expires_at, consumed_at
		FROM oidc_refresh_tokens WHERE token_hash = ?`), tokenHash).
		Scan(&rec.FamilyID, &rec.ClientID, &rec.Sub, &rec.Scope, &rec.SessionJTI, &authUnix, &expUnix, &consumedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lookup refresh token: %w", err)
	}
	rec.AuthTime = time.Unix(authUnix, 0)
	rec.ExpiresAt = time.Unix(expUnix, 0)
	if time.Now().After(rec.ExpiresAt) {
		return nil, ErrNotFound
	}
	if consumedAt.Valid {
		rec.Consumed = true
		return &rec, ErrReuseDetected
	}

	res, err := s.db.ExecContext(ctx, s.q(`
		UPDATE oidc_refresh_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL`),
		time.Now().Unix(), tokenHash)
	if err != nil {
		return nil, fmt.Errorf("consume refresh token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		rec.Consumed = true
		return &rec, ErrReuseDetected
	}
	rec.Consumed = false
	return &rec, nil
}

func (s *SQLStores) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM oidc_refresh_tokens WHERE family_id = ?`), familyID)
	if err != nil {
		return fmt.Errorf("revoke refresh family: %w", err)
	}
	return nil
}

func (s *SQLStores) RevokeBySub(ctx context.Context, sub string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM oidc_refresh_tokens WHERE sub = ?`), sub)
	if err != nil {
		return fmt.Errorf("revoke refresh by sub: %w", err)
	}
	return nil
}

func (s *SQLStores) GetConsent(ctx context.Context, sub, clientID string) (*Consent, error) {
	var c Consent
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT sub, client_id, scope FROM oidc_consents WHERE sub = ? AND client_id = ?`),
		sub, clientID).Scan(&c.Sub, &c.ClientID, &c.Scope)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get consent: %w", err)
	}
	return &c, nil
}

func (s *SQLStores) PutConsent(ctx context.Context, c Consent) error {
	scopeAssign := "excluded.scope"
	if s.dollar {
		scopeAssign = "EXCLUDED.scope"
	}
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO oidc_consents (sub, client_id, scope) VALUES (?, ?, ?)
		ON CONFLICT (sub, client_id) DO UPDATE SET scope = `+scopeAssign),
		c.Sub, c.ClientID, c.Scope)
	if err != nil {
		return fmt.Errorf("put consent: %w", err)
	}
	return nil
}

// Interface wrappers: SQLStores methods used as CodeStore have Put/Consume;
// RefreshStore needs Put named for refresh tokens. Use typed adapters.

type sqlCodeStore struct{ s *SQLStores }
type sqlRefreshStore struct{ s *SQLStores }
type sqlConsentStore struct{ s *SQLStores }

func (c sqlCodeStore) Put(ctx context.Context, codeHash string, code AuthCode) error {
	return c.s.Put(ctx, codeHash, code)
}
func (c sqlCodeStore) Consume(ctx context.Context, codeHash string) (*AuthCode, error) {
	return c.s.Consume(ctx, codeHash)
}

func (c sqlRefreshStore) Put(ctx context.Context, tokenHash string, rec RefreshRecord) error {
	return c.s.putRefresh(ctx, tokenHash, rec)
}
func (c sqlRefreshStore) Consume(ctx context.Context, tokenHash string) (*RefreshRecord, error) {
	return c.s.consumeRefresh(ctx, tokenHash)
}
func (c sqlRefreshStore) RevokeFamily(ctx context.Context, familyID string) error {
	return c.s.RevokeFamily(ctx, familyID)
}
func (c sqlRefreshStore) RevokeBySub(ctx context.Context, sub string) error {
	return c.s.RevokeBySub(ctx, sub)
}

func (c sqlConsentStore) Get(ctx context.Context, sub, clientID string) (*Consent, error) {
	return c.s.GetConsent(ctx, sub, clientID)
}
func (c sqlConsentStore) Put(ctx context.Context, cons Consent) error {
	return c.s.PutConsent(ctx, cons)
}

// AsStores exposes SQLStores as the three OIDC store interfaces.
func (s *SQLStores) AsStores() Stores {
	return Stores{
		Codes:    sqlCodeStore{s},
		Refresh:  sqlRefreshStore{s},
		Consents: sqlConsentStore{s},
	}
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
		return fmt.Errorf("create sqlite directory: %w", err)
	}
	return nil
}
