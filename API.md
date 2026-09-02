# Antosara Auth – API Reference

This document describes the HTTP API exposed by the auth service. All API routes are under the same origin as the service (e.g. `https://auth.example.com`).

**Base path:** All auth API routes are prefixed with `/api` unless noted.

**Content type:** Request bodies must be `Content-Type: application/json` where applicable. Success responses are `application/json` unless stated otherwise.

**CORS:** Allowed origins are configured via `CORS_ORIGINS`; credentials (cookies) are supported.

---

## Authentication

### Cookie-based (browser)

- **Login** (`POST /api/login`) sets an HTTP-only, secure cookie containing the JWT and a separate CSRF cookie.
- **Protected routes** require that cookie to be sent (same-origin or allowed CORS origin with credentials).
- **CSRF** is enforced only when the request carries the **auth cookie** (cookie-based session). For mutating requests (PUT, POST, DELETE) in that case, the **`X-CSRF-Token`** header must be sent and must match the session-bound CSRF token (and the CSRF cookie). GET/HEAD do not require the header. If the client uses only **`Authorization: Bearer`** (no auth cookie), CSRF is not applied.

### Bearer token

- Tokens can be sent in the **`Authorization: Bearer <token>`** header. When both cookie and header are present, the middleware uses the header.
- **Verify token** (`POST /api/verify-token`) is **disabled by default**. Set `ENABLE_VERIFY_TOKEN=true` to expose it. When enabled, it accepts the token in `Authorization: Bearer` or in a JSON body `{ "token": "<token>" }`. Prefer local verification via JWKS plus `POST /api/token/check-revocation`.
- For **Bearer-only** clients (e.g. mobile apps, server-to-server), **no CSRF token or cookie is required**; only a valid JWT in the header.

### Protected routes

The following routes require a valid, non-revoked JWT:

- `GET /api/profile`
- `PUT /api/profile`
- `POST /api/logout`

For **cookie-based** (browser) sessions, PUT and POST also require the **`X-CSRF-Token`** header to match the CSRF cookie. For **Bearer-only** clients, no CSRF header or cookie is needed.

---

## Health

| Method | Path     | Auth | Description                |
|--------|----------|------|----------------------------|
| `GET`  | `/health` | No   | Liveness/readiness probe. Returns 200. |

---

## Public endpoints

### JWKS (public keys for JWT verification)

| Method | Path                  | Auth | Description                                  |
|--------|-----------------------|------|----------------------------------------------|
| `GET`  | `/.well-known/jwks.json` | No   | Returns the public keys (JWK Set) used to verify RS256 JWTs. Rate-limited. |

**Response:** `200 OK`, `Content-Type: application/jwk-set+json`  
**Body:** JSON object with a `keys` array of JWKs (e.g. `kty`, `use`, `alg`, `kid`, `n`, `e`).

**Errors:** `503 Service Unavailable` if the key set cannot be loaded.

---

### Sign up

| Method | Path           | Auth | Description                                  |
|--------|----------------|------|----------------------------------------------|
| `POST` | `/api/signup`  | No   | Register with email and password. Sends a 6-digit verification code by email. Rate-limited. |

**Request body:**

```json
{
  "email": "user@example.com",
  "password": "YourSecureP4ss!"
}
```

- **email:** Valid email format, max 254 characters (normalized to lowercase).
- **password:** 8–128 characters; must include at least one uppercase letter, one lowercase letter, one number, and one special character from `!@#$%^&*`.

**Success (new user):** `200 OK`

```json
{
  "message": "User created successfully. Please check your email for verification.",
  "email": "user@example.com"
}
```

**Success (existing unverified user – code resent):** `200 OK`

```json
{
  "message": "Verification code resent",
  "email": "user@example.com"
}
```

**Errors:** `400 Bad Request` (invalid body, validation error, or existing verified user); `500 Internal Server Error` (e.g. email send failure).

---

### Verify email

| Method | Path               | Auth | Description                                                |
|--------|--------------------|------|------------------------------------------------------------|
| `POST` | `/api/verify-email`| No   | Verify email using the 6-digit code sent after signup. Rate-limited. |

**Request body:**

```json
{
  "email": "user@example.com",
  "password": "YourSecureP4ss!",
  "verification_code": "123456"
}
```

- **verification_code:** Exactly 6 numeric digits.

**Success:** `200 OK`

```json
{
  "message": "Email verified successfully"
}
```

**Errors:** `400 Bad Request` (invalid format, wrong code, expired code, or already verified); `401 Unauthorized` (invalid credentials).

---

### Login

| Method | Path          | Auth | Description                                                |
|--------|---------------|------|------------------------------------------------------------|
| `POST` | `/api/login`  | No   | Authenticate with email and password. On success, sets JWT and CSRF cookies and returns a JSON message. Rate-limited. |

**Request body:**

```json
{
  "email": "user@example.com",
  "password": "YourSecureP4ss!"
}
```

**Success:** `200 OK`. Response sets cookies (JWT + CSRF). Body:

```json
{
  "message": "Login successful"
}
```

**Errors:** `400 Bad Request` (invalid body or email format); `401 Unauthorized` (invalid credentials or email not verified); `429 Too Many Requests` (account lockout after repeated failures); `500 Internal Server Error` (e.g. token generation failure).

---

### Verify token

**Opt-in.** This route is not registered unless `ENABLE_VERIFY_TOKEN` is set to a truthy value (`1`, `true`, `yes`, `on`). Otherwise the path returns 404. JWTs can be verified independently via `GET /.well-known/jwks.json`; use `POST /api/token/check-revocation` for logout.

| Method | Path               | Auth | Description                                                |
|--------|--------------------|------|------------------------------------------------------------|
| `POST` | `/api/verify-token`| No   | Check if a JWT is valid (signature, claims, not revoked). Rate-limited. Requires `ENABLE_VERIFY_TOKEN`. |

**Token input (one of):**

- Header: `Authorization: Bearer <token>`
- Body: `{ "token": "<token>" }`

**Success:** `200 OK`

```json
{
  "valid": true
}
```

**Errors:** `400 Bad Request` (no token provided); `401 Unauthorized` (invalid or revoked token); `503 Service Unavailable` (e.g. key set or revocation check unavailable).

---

### Check revocation (by jti)

| Method | Path                         | Auth | Description                                                |
|--------|------------------------------|------|------------------------------------------------------------|
| `POST` | `/api/token/check-revocation`| No   | Check if a token is revoked by its JWT ID (`jti`). For use by services that already verified the JWT locally (e.g. via JWKS). Rate-limited. |

**Request body:**

```json
{
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Success:** `200 OK`

```json
{
  "revoked": true
}
```
or `{"revoked": false}`.

**Errors:** `400 Bad Request` (missing or empty `jti`); `503 Service Unavailable` (e.g. revocation store unavailable).

---

### Reset password (request link)

| Method | Path                 | Auth | Description                                                |
|--------|----------------------|------|------------------------------------------------------------|
| `POST` | `/api/reset-password`| No   | Request a password-reset link for the given email. If the email is registered, a link is sent. Rate-limited. |

**Request body:**

```json
{
  "email": "user@example.com"
}
```

**Success:** `200 OK`. Body is a plain-text message (e.g. "If your email is registered, you will receive a password reset link"). The same message is returned whether or not the email exists (to avoid enumeration).

**Errors:** `400 Bad Request` (invalid body or email); `500 Internal Server Error` (e.g. token generation or DB error).

---

### Confirm reset password

| Method | Path                        | Auth | Description                                                |
|--------|-----------------------------|------|------------------------------------------------------------|
| `POST` | `/api/reset-password/confirm` | No   | Set a new password using the token from the reset link. Rate-limited. |

**Request body:**

```json
{
  "token": "32-char-reset-token-from-email",
  "password": "NewSecureP4ss!"
}
```

- **token:** Exactly 32 characters (trimmed); the value from the reset link query parameter.
- **password:** Same rules as signup (8–128 chars, upper, lower, number, special).

**Success:** `200 OK`. Body is plain text: "Password has been reset successfully".

**Errors:** `400 Bad Request` (invalid token format, invalid/expired token, or password validation); `500 Internal Server Error` (e.g. DB error).

---

## Protected endpoints

All protected routes require a valid JWT (cookie or `Authorization: Bearer`). Cookie-based clients must also send the `X-CSRF-Token` header on mutating requests (PUT, POST). Bearer-only clients do not need CSRF.

---

### Profile (get)

| Method | Path             | Auth   | Description              |
|--------|------------------|--------|---------------------------|
| `GET`  | `/api/profile`   | JWT    | Return the current user’s profile. |

**Success:** `200 OK`

```json
{
  "email": "user@example.com",
  "alias": "Display Name",
  "verified": true
}
```

**Errors:** `401 Unauthorized` (missing or invalid token); `404 Not Found` (user not found).

---

### Profile (update)

| Method | Path             | Auth   | Description              |
|--------|------------------|--------|---------------------------|
| `PUT`  | `/api/profile`   | JWT (cookie-based: also send `X-CSRF-Token` header) | Update profile: alias and/or password. Current password required. |

**Request body:**

```json
{
  "currentPassword": "CurrentP4ss!",
  "newPassword": "NewSecureP4ss!",
  "alias": "New Display Name"
}
```

- **currentPassword:** Required. Must match the account password.
- **newPassword:** Optional. If present, must satisfy signup password rules.
- **alias:** Optional. Max 100 characters (UTF-8), trimmed.

**Success:** `200 OK`

```json
{
  "message": "Profile updated successfully"
}
```

**Errors:** `400 Bad Request` (invalid body, alias length, or password validation); `401 Unauthorized` (wrong current password or invalid token); `500 Internal Server Error` (e.g. DB error).

---

### Logout

| Method | Path           | Auth   | Description                                                |
|--------|----------------|--------|------------------------------------------------------------|
| `POST` | `/api/logout`  | JWT (cookie-based: also send `X-CSRF-Token` header) | Invalidate the current session (revoke token, clear CSRF), clear auth and CSRF cookies. |

**Success:** `200 OK`

```json
{
  "message": "Logged out successfully"
}
```

**Errors:** `401 Unauthorized` if the token is missing or invalid (middleware).

---

## Summary table

| Method | Path                        | Auth    | Description                    |
|--------|-----------------------------|---------|--------------------------------|
| `GET`  | `/health`                   | No      | Health check                   |
| `GET`  | `/.well-known/jwks.json`    | No      | Public keys for JWT verification |
| `POST` | `/api/signup`               | No      | Register; send verification code |
| `POST` | `/api/verify-email`         | No      | Verify email with code         |
| `POST` | `/api/login`                | No      | Login; set JWT + CSRF cookies  |
| `POST` | `/api/verify-token`         | No      | Check JWT validity (opt-in: `ENABLE_VERIFY_TOKEN`) |
| `POST` | `/api/token/check-revocation` | No    | Check if jti is revoked        |
| `POST` | `/api/reset-password`       | No      | Request password-reset email   |
| `POST` | `/api/reset-password/confirm` | No    | Set new password with token    |
| `GET`  | `/api/profile`              | JWT     | Get current user profile       |
| `PUT`  | `/api/profile`              | JWT (cookie: + `X-CSRF-Token`) | Update profile                 |
| `POST` | `/api/logout`               | JWT (cookie: + `X-CSRF-Token`) | Logout and revoke token        |

---

## Password rules

- Length: 8–128 characters.
- Must contain at least one of each: uppercase letter, lowercase letter, digit, and special character from `!@#$%^&*`.
- Must be valid UTF-8.

## Verification and reset tokens

- **Email verification code:** Exactly 6 numeric digits, sent by email after signup (or resent for existing unverified users).
- **Password reset token:** 32-character string (base64 URL-safe), sent in the reset link. Valid until expiry (configurable via `RESET_TOKEN_EXPIRY_MINUTES`).

## Rate limiting

Auth-related endpoints (signup, verify-email, login, token/check-revocation, reset-password, reset-password/confirm, and verify-token when enabled) and `/.well-known/jwks.json` are rate-limited per client IP (configurable via `RATE_LIMIT_REQUESTS_PER_MINUTE`). Excessive requests return `429 Too Many Requests`. Account lockout may also apply after repeated failed logins.
