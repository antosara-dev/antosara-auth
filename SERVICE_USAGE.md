# How other services use antosara-auth

**antosara-auth** runs as a **standalone API service**. Other applications (frontends, backends, mobile apps) use it by calling its HTTP API and, when they need to protect their own endpoints, by **verifying the JWTs** it issues.

---

## 1. Run the auth service

Deploy and run the auth service (see [README.md](README.md)). Other services do **not** import or embed it; they talk to it over HTTP.

- **Base URL:** e.g. `https://auth.yourdomain.com` (your auth service origin).
- **API:** [API.md](API.md) describes all endpoints (signup, login, verify-token, profile, logout, etc.).

---

## 2. Frontends / clients (login and calling auth API)

- **Web app:** Call `POST /api/login` with credentials. The auth service sets HTTP-only cookies (JWT + CSRF). For protected auth routes (profile, logout), send the cookie and, for mutating requests, the `X-CSRF-Token` header. Use same-origin or CORS-allowed origin with credentials.
- **Mobile / API-only clients:** Call `POST /api/login`; you cannot rely on cookies. Use the token returned in the response body if the auth service supports it, or call login from a backend that returns the token to the client. Then send `Authorization: Bearer <token>` to protected auth endpoints and to **your own** APIs (see below).
- **Signup, verify-email, reset-password:** Call the auth service’s public endpoints as described in [API.md](API.md).

---

## 3. Other backends: protecting your APIs with the same JWT

The auth service issues RS256 JWTs. Any other service (Go, Node, Python, etc.) that receives a JWT in `Authorization: Bearer <token>` can **verify** it and then trust the claims (e.g. `email`, `sub`, `jti`).

### Option A: Verify using the JWKS endpoint (recommended)

1. **Fetch the public keys** from the auth service:
   ```http
   GET https://auth.yourdomain.com/.well-known/jwks.json
   ```
   Response is a JWK Set (JSON with a `keys` array). Keys include `kid`, `alg`, `n`, `e` for RS256.

2. **When a request arrives** with `Authorization: Bearer <token>`:
   - Decode the JWT header (e.g. base64url), read `kid`.
   - Find the key in the JWK Set with that `kid`.
   - Verify the JWT signature with that key and validate `exp` / `nbf` (and optionally `iss`, `aud`).
   - Use claims such as `email`, `sub`, `jti` for authorization.

This supports key rotation: the auth service can add new keys to the set; tokens carry `kid` so verifiers pick the right key.

### Option B: Single public key

If you don’t need rotation, you can configure your service with the auth service’s **single** public key (same as `JWT_PUBLIC_KEY` in the auth secret). Verify the JWT with that key (RS256). You must update your config when the auth service rotates keys.

### Example (Go) with JWKS

Use a JWT library that supports JWKS (e.g. `github.com/lestrrat-go/jwx`) and pass the JWKS URL or the fetched key set. 

- Fetch `/.well-known/jwks.json` once (or periodically) and build a key set.
- On each request: parse the token with that key set, validate expiry/issuer, then read claims.

### Example (Node, Python, etc.)

Use a JWT library that supports RS256 and either:

- JWKS (fetch from `/.well-known/jwks.json` and resolve by `kid`), or  
- A single PEM public key.

Verify signature and standard claims, then use `email` / `sub` for identity.

---

## 4. Trust boundaries

- **Issuer (`iss`):** The auth service sets `iss` from its config (`JWT_ISSUER`). Your services should only accept tokens with `iss` equal to your auth service’s issuer (e.g. `https://auth.yourdomain.com`).
- **Audience:** The auth service can set `aud` (e.g. to the user’s email). Optionally enforce `aud` in your APIs.
- **Revocation:** The auth service revokes tokens on logout and stores them (e.g. in DynamoDB). To respect revocation in **your** service you can:
  - **Check by jti (recommended):** After verifying the JWT locally (e.g. via JWKS), call **POST /api/token/check-revocation** with body `{"jti": "<jti>"}`. Response is `{"revoked": true}` or `{"revoked": false}`. One lightweight call per request (or cache per jti with short TTL).
  - **Full token check:** Call **POST /api/verify-token** with the bearer token; it validates signature, claims, and revocation and returns `{"valid": true}`. Use this if you prefer not to verify the JWT yourself.
  - **Go:** Use the provided client: `import "github.com/antosara-dev/antosara-auth/pkg/client"` and call `client.CheckRevoked(ctx, authServiceBaseURL, jti)` (see section 5).

---

## 5. Using the Go module (optional)

**Module path:** `github.com/antosara-dev/antosara-auth`

- **`pkg/client` package:** Helpers to call the auth service from Go.
  - **Revocation check:** `client.CheckRevoked(ctx, authServiceBaseURL, jti)` calls **POST /api/token/check-revocation** and returns `(revoked bool, err error)`. Use after verifying the JWT locally (e.g. via JWKS). Optional: `client.CheckRevokedWithClient(ctx, httpClient, baseURL, jti)` to use a custom `*http.Client`.
  ```go
  import "github.com/antosara-dev/antosara-auth/pkg/client"

  revoked, err := client.CheckRevoked(ctx, "https://auth.example.com", jti)
  if err != nil { /* handle */ }
  if revoked { /* reject request */ }
  ```
- **`pkg` package:** Types and interfaces used by the auth service:
  - `User`, `UserRepository`, `TokenRevocationRepository`, `SessionCSRFRepository`, and shared errors.
  - Import `github.com/antosara-dev/antosara-auth/pkg` if you need the same types (e.g. to implement a custom repository). The auth service’s **HTTP handlers** live in `internal`, which is **not** importable by other modules.
- **Depending on the module:** If the repo is private, set `GOPRIVATE` and use a token or `replace` in `go.mod` as needed.

Most consumers only need the HTTP API and JWT verification (sections 2 and 3); use `pkg/client` when you want revocation checks from Go without building the request yourself.

---

## Summary

| Consumer            | How they use the auth service |
|--------------------|-------------------------------|
| Web frontend       | Call signup/login/verify/reset/profile/logout; use cookies + CSRF or token; same-origin or CORS with credentials. |
| Mobile / SPA       | Call login (or backend proxy); get token; send `Authorization: Bearer <token>` to auth and to your APIs. |
| Your backend APIs  | Read `Authorization: Bearer <token>`; verify JWT with JWKS from `GET /.well-known/jwks.json` (or single public key); optionally check revocation via `POST /api/token/check-revocation` with `jti`. |
| Go services        | Verify JWTs as above; use `pkg/client.CheckRevoked(ctx, authURL, jti)` for revocation. Optionally import `pkg` for types. |

For full endpoint and request/response details, see [API.md](API.md).
