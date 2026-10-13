# OIDC Identity Provider (`/oidc-idp`)

This service can act as an **OpenID Connect Identity Provider** in addition to the first-party `/api` JWT auth API. The two surfaces are separate:

| | `/api` | `/oidc-idp` |
|---|---|---|
| Purpose | First-party email/password API | OIDC Authorization Code flow for relying parties |
| Tokens | Cookie JWT: `iss=JWT_ISSUER`, `aud=email`, `type=JWT_TYPE` | ID token (`aud=client_id`) + access token (`aud` = OIDC issuer). No `type=JWT_TYPE` |
| Login | `POST /api/login` JSON | Browser login/consent pages under `/oidc-idp` |
| Keys | Same RS256 keys; `GET /.well-known/jwks.json` | Same JWKS (`jwks_uri` points at the existing endpoint) |

Do not send OIDC access or ID tokens to `/api/profile` or `/api/logout`. Do not send `/api` JWTs to `/oidc-idp/userinfo`.

---

## Discovery

Issuer (default): `https://$HOST_NAME/oidc-idp`  
Override with `OIDC_ISSUER` (no trailing slash).

```http
GET /oidc-idp/.well-known/openid-configuration
```

`jwks_uri` is `https://<host>/.well-known/jwks.json` (the existing JWKS endpoint).

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oidc-idp/.well-known/openid-configuration` | Discovery document |
| GET, POST | `/oidc-idp/authorize` | Authorization Code + PKCE |
| POST | `/oidc-idp/token` | `authorization_code` and `refresh_token` |
| GET, POST | `/oidc-idp/userinfo` | UserInfo (OIDC access token) |
| GET, POST | `/oidc-idp/end_session` | RP-initiated logout |
| GET, POST | `/oidc-idp/login` | Login UI (browser) |
| GET, POST | `/oidc-idp/consent` | Consent UI (browser) |

Supported: `response_type=code`, PKCE `S256` (required), scopes `openid` (required), `profile`, `email`, `offline_access`.  
`prompt`: `login`, `consent`, `none` (and combinations except `none` with others).  
Client auth at the token endpoint: `client_secret_basic`, `client_secret_post`, `none` (public clients).

Implicit, hybrid, device code, PAR, and dynamic client registration are not implemented.

---

## Clients

v1 clients are **static**. Load a JSON array from `OIDC_CLIENTS` or `OIDC_CLIENTS_FILE` (`OIDC_CLIENTS` wins if both are set). Storage interfaces are in place so a database-backed registry can be added later.

```json
[
  {
    "client_id": "web-app",
    "client_secret": "replace-me",
    "redirect_uris": ["https://app.example.com/callback"],
    "post_logout_redirect_uris": ["https://app.example.com/logout"],
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code", "refresh_token"]
  },
  {
    "client_id": "spa",
    "redirect_uris": ["https://spa.example.com/callback"],
    "public": true,
    "token_endpoint_auth_method": "none"
  }
]
```

- `redirect_uri` and `post_logout_redirect_uri` must match a registered value **exactly**.
- Confidential `client_secret` may be plaintext (hashed with bcrypt at load) or a bcrypt hash (`$2a$` / `$2b$` / `$2y$`).
- Public clients must use PKCE and `token_endpoint_auth_method=none`.

---

## Authorization Code flow

1. Redirect the browser to `/oidc-idp/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope` (must include `openid`), `state`, `nonce` (recommended), `code_challenge`, `code_challenge_method=S256`. Optional `prompt`.
2. If the user already has a first-party `auth_token` cookie (from `/api/login` or OIDC login) and `prompt` does not include `login`, login is skipped.
3. Consent is shown unless the same user already granted the requested scopes to that client, or `prompt=consent` forces it. `prompt=none` never shows UI: it redirects with `login_required` or `consent_required`.
4. The IdP redirects to `redirect_uri?code=...&state=...`.
5. The relying party `POST`s `/oidc-idp/token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`, and client authentication.
6. Response: `id_token`, `access_token`, `token_type=Bearer`, `expires_in`, `scope`, and `refresh_token` when `offline_access` was granted.

Authorization codes are hashed, single-use, and short-lived (default 60s). Reuse returns `invalid_grant`.

**ID token claims:** `iss` = OIDC issuer, `sub` = normalized email (the user primary key), `aud` = `client_id`, `exp`/`iat`/`auth_time`, `nonce` if supplied, `at_hash`, plus `email` / `email_verified` and `name` / `preferred_username` (alias) when those scopes were granted.

**Access token:** JWT with `iss` = OIDC issuer, `aud` = OIDC issuer, `token_use=access`, `client_id`, `scope`, `sub`. Use it only at `/oidc-idp/userinfo`.

---

## Refresh tokens

Issued only with scope `offline_access`. Stored hashed. Each use **rotates** the token. Reuse of an already-rotated token revokes the whole family and returns `invalid_grant`.

---

## Logout

```http
GET /oidc-idp/end_session?id_token_hint=<id_token>&post_logout_redirect_uri=<uri>&state=<state>
```

Validates `id_token_hint` when present, revokes the first-party session (`jti`) like `/api/logout`, revokes that user's OIDC refresh tokens, then redirects if `post_logout_redirect_uri` is registered for the client (`client_id` or `aud` from the hint). Otherwise a simple signed-out page is shown.

---

## Configuration

| Variable | Meaning |
|----------|---------|
| `OIDC_ISSUER` | Issuer URL. Default `https://$HOST_NAME/oidc-idp` |
| `OIDC_CLIENTS` | JSON array of clients |
| `OIDC_CLIENTS_FILE` | Path to a JSON file (used if `OIDC_CLIENTS` is unset) |
| `OIDC_ID_TOKEN_TTL` | ID token lifetime (Go duration or seconds). Default 15m |
| `OIDC_ACCESS_TOKEN_TTL` | Access token lifetime. Default 1h |
| `OIDC_AUTH_CODE_TTL` | Authorization code lifetime. Default 60s |
| `OIDC_REFRESH_TOKEN_TTL` | Refresh token lifetime. Default 720h |
| `OIDC_PENDING_TTL` | Login/consent pending-request cookie lifetime. Default 10m |

JWT signing still uses `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` (unchanged). `JWT_ISSUER` continues to apply only to `/api` tokens.

Browser SPAs that call `/oidc-idp/token` from another origin must be listed in `CORS_ORIGINS`. CORS is not widened automatically from redirect URIs.

## Local test relying party

Disabled by default. Set `ENABLE_OIDC_RP=true` (also `1`, `yes`, or `on`) to serve a test app at:

**http://localhost:5000/oidc-rp**

That also registers two clients:

- `oidc-rp` (`public: true`) — browser PKCE; redirect `http://localhost:<port>/oidc-rp`
- `oidc-rp-confidential` (`public: false`) — server callback `http://localhost:<port>/oidc-rp/callback` exchanges the code with HTTP Basic (`oidc-rp-dev-secret`). Use **Sign in (confidential)** on the test page.

Do not enable this in production.

### Storage

PostgreSQL and SQLite create `oidc_auth_codes`, `oidc_refresh_tokens`, and `oidc_consents` on startup. DynamoDB requires tables `OIDCAuthCodes`, `OIDCRefreshTokens`, and `OIDCConsents` (see `scripts/terraform`).
