package internal

import (
	"fmt"

	"github.com/antosara-dev/antosara-auth/internal/oidc"
)

// NewOIDCStores creates authorization-code, refresh-token, and consent stores
// for the configured DB_BACKEND. Existing user/revocation/CSRF repositories
// are unchanged.
func NewOIDCStores() (oidc.Stores, error) {
	cfg, err := LoadStorageConfig()
	if err != nil {
		return oidc.Stores{}, err
	}

	switch cfg.Backend {
	case BackendDynamoDB:
		dyn, err := oidc.NewDynamoStores()
		if err != nil {
			return oidc.Stores{}, err
		}
		return dyn.AsStores(), nil
	case BackendPostgres:
		sqlStores, err := oidc.NewSQLStores("pgx", cfg.PostgresDSN)
		if err != nil {
			return oidc.Stores{}, err
		}
		return sqlStores.AsStores(), nil
	case BackendSQLite:
		sqlStores, err := oidc.NewSQLStores("sqlite", cfg.SQLiteDSN)
		if err != nil {
			return oidc.Stores{}, err
		}
		return sqlStores.AsStores(), nil
	default:
		return oidc.Stores{}, fmt.Errorf("unsupported DB_BACKEND %q", cfg.Backend)
	}
}
