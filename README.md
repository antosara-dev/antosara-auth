# Antosara Auth

A **Go-based API service** for authentication and user management: signup, login, email verification, and password recovery. It issues **RS256 JWTs** that other services can verify (e.g. via the `/.well-known/jwks.json` endpoint or a shared public key) to protect their own APIs. Frontends and mobile apps can call this service for login and profile while backends can validate the bearer token and use the claims for identity.

**Stack:** Go; storage backends DynamoDB, PostgreSQL, and SQLite (users, tokens, CSRF); optional AWS Secrets Manager (config); SMTP/SES (email). Configuration comes from the process environment and an optional local `.env`, or from a single Secrets Manager secret if `AWS_SECRET_ARN` / `AWS_SECRET_NAME` is set.

- **API reference:** [API.md](API.md)
- **Using this service (frontends, backends, token verification):** [SERVICE_USAGE.md](SERVICE_USAGE.md)

---

## Configuration

Config is loaded at startup in this order:

1. **Process environment** (Docker, Kubernetes, systemd, exported shell vars).
2. **Local `.env`** in the working directory, if present. Already-set process variables are not overwritten. Copy [.env.example](.env.example) to `.env` for local development.
3. **AWS Secrets Manager** (optional). If `AWS_SECRET_ARN` or `AWS_SECRET_NAME` is set, the secret is fetched and overwrites matching variables. Other settings (JWT keys, email, CORS, etc.) live **inside that secret**; see [Secret format](#secret-format).

For a full list of variable names and meanings, see [.env.example](.env.example).

---

## Database backends

Set `DB_BACKEND` to choose storage. The default is `dynamodb`. PostgreSQL and SQLite create their schema on startup; DynamoDB tables must already exist.

| `DB_BACKEND` | Use | Required settings |
|---|---|---|
| `dynamodb` (default) | AWS DynamoDB tables `Users`, `RevokedTokens`, `SessionCSRF` | `AWS_REGION` (and AWS credentials). Tables must exist; see `scripts/terraform`. |
| `postgres` | PostgreSQL | `DATABASE_URL`, or `POSTGRES_HOST` + `POSTGRES_USER` + `POSTGRES_DB` (optional `POSTGRES_PORT`, `POSTGRES_PASSWORD`, `POSTGRES_SSLMODE`). |
| `sqlite` (alias `sqlite3`) | SQLite file (or in-memory DSN) | `SQLITE_PATH`, `SQLITE_DSN`, or `DATABASE_URL`. |

Examples:

```bash
# DynamoDB (default)
DB_BACKEND=dynamodb
AWS_REGION=us-west-2

# PostgreSQL
DB_BACKEND=postgres
DATABASE_URL=postgres://antosara:password@localhost:5432/antosara_auth?sslmode=disable

# SQLite
DB_BACKEND=sqlite
SQLITE_PATH=./data/antosara-auth.db
```

---

## Local: run with Docker

Use the provided Docker Compose to run the auth service **locally**. You can inject config via Compose `environment` / `env_file`, or load it from AWS Secrets Manager.

### 1. Create the secret in AWS Secrets Manager

Create a secret whose value is a **JSON object** with all required keys (see [Secret format](#secret-format)). It is recommended to keep
dev and prod secrets separate.

### 2. Configure Docker Compose (**local dev**)

Edit [docker-compose.yml](docker-compose.yml) and set:

- **AWS_REGION** – e.g. `us-west-2`
- **AWS_SECRET_ARN** – your secret’s name or full ARN (copy the secret ARN from the AWS console)

If you use Secrets Manager, credentials are provided by mounting your host `~/.aws` into the container. If you inject all config via `environment` or `env_file` instead, omit `AWS_SECRET_ARN` / `AWS_SECRET_NAME`.

### 3. Run

```bash
docker compose up --build
```

Service is at `http://localhost:5000`. Health: `http://localhost:5000/health`.

```bash
# Detached
docker compose up -d

# Logs
docker compose logs -f antosara-auth

# Stop
docker compose down
```

### Optional: override without editing compose

To avoid putting secrets in the repo, use a `.env` file. Compose reads `.env` for variable substitution, and the app also loads `.env` from the working directory when you run locally. For the container, add `env_file: [ .env ]` under the service in `docker-compose.yml` (the image does not include `.env`).

```bash
AWS_REGION=us-west-2
AWS_SECRET_ARN=your-secret-name-or-arn
```

If `AWS_SECRET_ARN` / `AWS_SECRET_NAME` is set, the app overlays config from Secrets Manager; otherwise it uses the environment (and `.env`) as-is.

---

## Production

In production you typically do **not** ship a `.env` file. Inject configuration as environment variables (Kubernetes secrets, ECS task definition, etc.) or via AWS Secrets Manager.

**Process environment:** set the variables from [.env.example](.env.example) and leave `AWS_SECRET_ARN` / `AWS_SECRET_NAME` unset.

**AWS Secrets Manager:** set only:

| Variable           | Description                          |
|-------------------|--------------------------------------|
| `AWS_REGION`      | Region for Secrets Manager (and DynamoDB/SES). |
| `AWS_SECRET_ARN`  | Secret name or ARN in Secrets Manager. |

All other configuration (JWT keys, `EMAIL_*`, `HOST_NAME`, `CORS_ORIGINS`, etc.) must be stored **inside that secret** as a JSON object. The app fetches it on startup and uses it as the process environment.

### Credentials in production

- **Service runs on AWS (ECS, EKS, App Runner, etc.):** Attach an IAM role to the task/pod with the permissions below. Do **not** set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
- **Service runs outside AWS:** Inject AWS credentials via your platform’s secret mechanism (e.g. env vars from a secret store, kubernetes secrets etc). Use an IAM user with the permissions below. Do **not** mount `~/.aws` or commit keys.

### Required IAM permissions

The IAM user or role used by the auth service (task role, instance profile, or injected credentials) must have at least the following when you use AWS services. DynamoDB permissions apply only if `DB_BACKEND=dynamodb`. Secrets Manager permissions apply only if you load config from a secret.

**Secrets Manager**

- `secretsmanager:GetSecretValue` on the secret used by the app (resource: the secret’s ARN).

**DynamoDB**

The service uses three tables: `Users`, `RevokedTokens`, `SessionCSRF`. Minimum actions:

- `dynamodb:DescribeTable`
- `dynamodb:GetItem`
- `dynamodb:PutItem`
- `dynamodb:UpdateItem`
- `dynamodb:DeleteItem`
- `dynamodb:Query`
- `dynamodb:UpdateTimeToLive` (optional; used best-effort to enable TTL on RevokedTokens and SessionCSRF)

Scope the policy to the table ARNs in your account/region (e.g. `arn:aws:dynamodb:REGION:ACCOUNT:table/Users`, and the same for `RevokedTokens` and `SessionCSRF`).

**SMTP (email)**

User verification and password recovery needs email SMTP settings. Use your preferred mail provider.
If using SES SMTP for email, follow instructions to setup the SMTP interface https://docs.aws.amazon.com/ses/latest/dg/send-email-smtp.html 

**Example minimal policy (replace REGION, ACCOUNT, SECRET_ARN, and table names as needed)**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:SECRET_ARN"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:REGION:ACCOUNT:table/*/index/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:UpdateTimeToLive",
        "dynamodb:DescribeTimeToLive"
      ],
      "Resource": [
        "arn:aws:dynamodb:REGION:ACCOUNT:table/*"
      ]
    }
  ]
}
```

### Checklist

**Secrets & config**

- [ ] All required keys are available: either as process environment variables or inside an AWS Secrets Manager secret (see [Secret format](#secret-format)).
- [ ] Config includes JWT keys, email settings, `HOST_NAME`, `JWT_ISSUER`, and any CORS/cookie/password-reset URL you need.
- [ ] No `.env` file committed or baked into the image. If using Secrets Manager, only `AWS_REGION` and `AWS_SECRET_ARN` (or `AWS_SECRET_NAME`) need to be set in the run environment.

**IAM** (when `DB_BACKEND=dynamodb`, and when using Secrets Manager or SES)

- [ ] IAM role or user has the [required permissions](#required-iam-permissions) for DynamoDB (tables `Users`, `RevokedTokens`, `SessionCSRF`). Include Secrets Manager (`GetSecretValue`) only if you load config from a secret. Include SES (`SendRawEmail`) if you send mail via SES.

**Infrastructure**

- [ ] **DynamoDB:** tables `Users`, `RevokedTokens`, and `SessionCSRF` exist in the same region (e.g. via [scripts/terraform](scripts/terraform)).
- [ ] **PostgreSQL:** database exists and the service can connect (`DATABASE_URL` or `POSTGRES_*`). Schema is created on startup.
- [ ] **SQLite:** `SQLITE_PATH` / `SQLITE_DSN` is writable. Schema is created on startup.

**Production hardening**

- [ ] `CORS_ORIGINS`, `COOKIE_DOMAIN`, and `PASSWORD_RESET_URL` in the secret match your real front-end and reset page.
- [ ] `JWT_ISSUER` and `HOST_NAME` in the secret match your production host.

---

## Secret format

The secret value must be a **single JSON object**. Keys are environment variable names; values are strings.

Example (minimal):

```json
{
  "JWT_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
  "JWT_PUBLIC_KEY": "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
  "AWS_REGION": "REGION",
  "HOST_NAME": "auth.example.com",
  "JWT_ISSUER": "https://auth.example.com",
  "JWT_TYPE": "access",
  "JWT_ALGORITHM": "RS256",
  "JWT_EXPIRY_HOURS": "24",
  "EMAIL_HOST": "email-smtp.REGION.amazonaws.com",
  "EMAIL_HOST_PORT": "587",
  "EMAIL_HOST_USER": "...",
  "EMAIL_HOST_PASSWORD": "...",
  "EMAIL_SENDER": "noreply@example.com",
  "CORS_ORIGINS": "https://app.example.com",
  "PASSWORD_RESET_URL": "https://app.example.com/new-password.html"
}
```

- For **JWT_PRIVATE_KEY** and **JWT_PUBLIC_KEY**, you can use literal `\n` in the string; the app replaces them with real newlines before use.
- For the full list of supported keys and descriptions, see [.env.example](.env.example).

---

## JWT key rotation

One private key has exactly one public key. **JWT_PUBLIC_KEYS** is for **key rotation**: you have multiple key pairs (current + previous) and list multiple **public** keys so tokens signed with either private key still verify.

- **Public key for your current private key** (for `JWT_PUBLIC_KEY` in the secret):
  ```bash
  openssl rsa -in jwt_private_key.pem -pubout -out jwt_public_key.pem
  ```
- **Rotation:** Add a second key pair; put both public keys in the secret under `JWT_PUBLIC_KEYS` (concatenate PEM blocks, e.g. with `\n` between blocks). Sign with the current private key; the app verifies using any key in the set.

---

## Generating RSA keys

**Linux / macOS:**

```bash
chmod +x scripts/generate-rsa-keys.sh
./scripts/generate-rsa-keys.sh
```

**Windows (PowerShell):**

```powershell
.\scripts\generate-rsa-keys.ps1
```

**Manual (OpenSSL):**

```bash
openssl genrsa -out jwt_private_key.pem 2048
openssl rsa -in jwt_private_key.pem -pubout -out jwt_public_key.pem
```

Put the PEM contents into `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` in the process environment, or in your AWS Secrets Manager secret if you use one.

---

## Building the image

```bash
docker build -t antosara-auth:latest .
```

To run the built image, provide configuration as environment variables (see [.env.example](.env.example)). If you use Secrets Manager, set `AWS_REGION` and `AWS_SECRET_ARN` (or `AWS_SECRET_NAME`) and provide AWS credentials (IAM role or env vars); all other config then comes from the secret.

---

## Other

- **Database:** DynamoDB tables must exist in AWS (`scripts/terraform`). PostgreSQL and SQLite create schema on startup; see [Database backends](#database-backends).
- **Local dev without Docker:** Copy `.env.example` to `.env`, fill in values (including `DB_BACKEND`), and run `cmd/antosara-auth/main.go` (e.g. from VS Code/Cursor). If `AWS_SECRET_ARN` or `AWS_SECRET_NAME` is set, you also need AWS credentials (e.g. `~/.aws` or env) so the app can fetch the secret.
