package internal

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/antosara-dev/antosara-auth/pkg"
)

type Backend string

const (
	BackendDynamoDB Backend = "dynamodb"
	BackendPostgres Backend = "postgres"
	BackendSQLite   Backend = "sqlite"
)

// StorageConfig holds repository backend settings loaded from the environment.
type StorageConfig struct {
	Backend Backend
	// PostgresDSN is set when Backend is postgres.
	PostgresDSN string
	// SQLiteDSN is set when Backend is sqlite.
	SQLiteDSN string
}

// LoadStorageConfig reads DB_BACKEND and backend-specific connection settings from the environment.
func LoadStorageConfig() (StorageConfig, error) {
	backend := Backend(strings.ToLower(strings.TrimSpace(os.Getenv("DB_BACKEND"))))
	if backend == "" {
		backend = BackendDynamoDB
	}

	switch backend {
	case BackendDynamoDB:
		return StorageConfig{Backend: BackendDynamoDB}, nil
	case BackendPostgres:
		dsn, err := postgresDSN()
		if err != nil {
			return StorageConfig{}, err
		}
		return StorageConfig{Backend: BackendPostgres, PostgresDSN: dsn}, nil
	case BackendSQLite, Backend("sqlite3"):
		dsn, err := sqliteDSN()
		if err != nil {
			return StorageConfig{}, err
		}
		return StorageConfig{Backend: BackendSQLite, SQLiteDSN: dsn}, nil
	default:
		return StorageConfig{}, fmt.Errorf("unsupported DB_BACKEND %q (use dynamodb, postgres, or sqlite)", backend)
	}
}

func postgresDSN() (string, error) {
	if dsn := strings.TrimSpace(os.Getenv("DATABASE_URL")); dsn != "" {
		return dsn, nil
	}

	host := strings.TrimSpace(os.Getenv("POSTGRES_HOST"))
	user := strings.TrimSpace(os.Getenv("POSTGRES_USER"))
	password := os.Getenv("POSTGRES_PASSWORD")
	dbName := strings.TrimSpace(os.Getenv("POSTGRES_DB"))

	if host == "" || user == "" || dbName == "" {
		return "", fmt.Errorf("postgres backend requires DATABASE_URL or POSTGRES_HOST, POSTGRES_USER, and POSTGRES_DB")
	}

	port := strings.TrimSpace(os.Getenv("POSTGRES_PORT"))
	if port == "" {
		port = "5432"
	}

	sslmode := strings.TrimSpace(os.Getenv("POSTGRES_SSLMODE"))
	if sslmode == "" {
		sslmode = "disable"
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Host:   fmt.Sprintf("%s:%s", host, port),
		Path:   dbName,
	}
	q := u.Query()
	q.Set("sslmode", sslmode)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// NewRepositories creates user, token-revocation, and CSRF repositories for the configured backend.
func NewRepositories() (pkg.UserRepository, pkg.TokenRevocationRepository, pkg.SessionCSRFRepository, error) {
	cfg, err := LoadStorageConfig()
	if err != nil {
		return nil, nil, nil, err
	}

	switch cfg.Backend {
	case BackendDynamoDB:
		return newDynamoDBRepositories()
	case BackendPostgres:
		return newPostgresRepositories(cfg.PostgresDSN)
	case BackendSQLite:
		return newSQLiteRepositories(cfg.SQLiteDSN)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported DB_BACKEND %q", cfg.Backend)
	}
}

func newDynamoDBRepositories() (pkg.UserRepository, pkg.TokenRevocationRepository, pkg.SessionCSRFRepository, error) {
	userRepo, err := NewDynamoDBUserRepository()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dynamodb user repository: %w", err)
	}

	tokenRevokeRepo, err := NewDynamoDBTokenRevocationRepository()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dynamodb token revocation repository: %w", err)
	}

	csrfRepo, err := NewDynamoDBSessionCSRFRepository()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dynamodb session csrf repository: %w", err)
	}

	return userRepo, tokenRevokeRepo, csrfRepo, nil
}

func sqliteDSN() (string, error) {
	if dsn := strings.TrimSpace(os.Getenv("SQLITE_DSN")); dsn != "" {
		return dsn, nil
	}
	if path := strings.TrimSpace(os.Getenv("SQLITE_PATH")); path != "" {
		return path, nil
	}
	if dsn := strings.TrimSpace(os.Getenv("DATABASE_URL")); dsn != "" {
		return dsn, nil
	}

	return "", fmt.Errorf("sqlite backend requires SQLITE_PATH, SQLITE_DSN, or DATABASE_URL")
}

func newPostgresRepositories(dsn string) (pkg.UserRepository, pkg.TokenRevocationRepository, pkg.SessionCSRFRepository, error) {
	userRepo, tokenRevokeRepo, csrfRepo, err := NewPostgresRepositories(dsn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("postgres repositories: %w", err)
	}
	return userRepo, tokenRevokeRepo, csrfRepo, nil
}

func newSQLiteRepositories(dsn string) (pkg.UserRepository, pkg.TokenRevocationRepository, pkg.SessionCSRFRepository, error) {
	userRepo, tokenRevokeRepo, csrfRepo, err := NewSQLiteRepositories(dsn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sqlite repositories: %w", err)
	}
	return userRepo, tokenRevokeRepo, csrfRepo, nil
}
