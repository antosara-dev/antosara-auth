# Antosara Auth

A Golang based service that provides API for secure authentication and user management (signup, login, email verification, password recovery).
This is opinionated and assumes AWS DynamoDB backend and AWS Secrets Manager

**Module path:** `github.com/antosara-dev/antosara-auth`

**API documentation:** [API.md](API.md)

---

## How configuration works

The service does **not** read a local `.env` file though `.env.example` is provided for a list of environment variables required. It loads all configuration from **AWS Secrets Manager** at startup.

- You set **only** `AWS_REGION` and `AWS_SECRET_ARN` (or `AWS_SECRET_NAME`) in the environment.
- The app fetches the secret, and sets each key–value pair as environment variables.
- All other settings (JWT keys, email, CORS, etc.) live **inside that secret**; see [Secret format](#secret-format) below.

For a full list of variable names and meanings, see [.env.example](.env.example).

---

## Local: run with Docker

Use the provided Docker Compose to run the auth service **locally**. It needs to talk to AWS (Secrets Manager, DynamoDB, SES), so you must have AWS credentials and point to your secret.

### 1. Create the secret in AWS Secrets Manager

Create a secret whose value is a **JSON object** with all required keys (see [Secret format](#secret-format)). It is recommended to keep
dev and prod secrets separate.

### 2. Configure Docker Compose (**local dev**)

Edit [docker-compose.yml](docker-compose.yml) and set:

- **AWS_REGION** – e.g. `us-west-2`
- **AWS_SECRET_ARN** – your secret’s name or full ARN (copy the secret ARN from the AWS console)

Credentials are provided by mounting your host `~/.aws` into the container so the app can call Secrets Manager, DynamoDB, and SES. No `.env` file is required for the app; the app always loads config from the secret.

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

To avoid putting your secret ARN in the repo, you can use a `.env` file **only for Docker Compose** (Compose injects it into the container). Create a `.env` in the project root with:

```bash
AWS_REGION=us-west-2
AWS_SECRET_ARN=your-secret-name-or-arn
```

Add `env_file: [ .env ]` under the service in `docker-compose.yml` if you prefer this over hardcoding in `environment`. The **application** still ignores `.env` and loads everything from Secrets Manager; this only supplies the two variables the container needs to find the secret.

---

## Production: no .env, only AWS Secrets

In production you do **not** use a `.env` file. You only set two things in the deployment environment (e.g. ECS, Kubernetes deployment, or your host’s env):

| Variable           | Description                          |
|-------------------|--------------------------------------|
| `AWS_REGION`      | Region for Secrets Manager (and DynamoDB/SES). |
| `AWS_SECRET_ARN`  | Secret name or ARN in Secrets Manager. |

All other configuration (JWT keys, `EMAIL_*`, `HOST_NAME`, `CORS_ORIGINS`, etc.) must be stored **inside that secret** as a JSON object. The app fetches it on startup and uses it as the process environment.

### Credentials in production

- **Service runs on AWS (ECS, EKS, App Runner, etc.):** Attach an IAM role to the task/pod with the permissions below. Do **not** set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
- **Service runs outside AWS:** Inject AWS credentials via your platform’s secret mechanism (e.g. env vars from a secret store, kubernetes secrets etc). Use an IAM user with the permissions below. Do **not** mount `~/.aws` or commit keys.

### Required IAM permissions

The IAM user or role used by the auth service (task role, instance profile, or injected credentials) must have at least the following.

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

- [ ] Secret created in AWS Secrets Manager with all required keys (see [Secret format](#secret-format)).
- [ ] Secret contains JWT keys, email config, `HOST_NAME`, `JWT_ISSUER`, and any CORS/cookie/password-reset URL you need.
- [ ] Only `AWS_REGION` and `AWS_SECRET_ARN` (or `AWS_SECRET_NAME`) are set in the run environment; no `.env` file in production.

**IAM**

- [ ] IAM role or user has the [required permissions](#required-iam-permissions): Secrets Manager (`GetSecretValue`), DynamoDB (tables `Users`, `RevokedTokens`, `SessionCSRF`), and SES (`SendRawEmail`).

**Infrastructure**

- [ ] DynamoDB tables `Users`, `RevokedTokens`, and `SessionCSRF` exist in the same region (e.g. via [scripts/terraform](scripts/terraform)).

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

Put the PEM contents into the corresponding keys in your **AWS Secrets Manager** secret (for production and for local Docker, since the app always uses the secret).

---

## Building the image

```bash
docker build -t antosara-auth:latest .
```

To run the built image you must set `AWS_REGION` and `AWS_SECRET_ARN` (or `AWS_SECRET_NAME`) and provide AWS credentials (e.g. IAM role or env vars). All other config comes from the secret.

---

## Other

- **DynamoDB:** Tables must exist in AWS. See `scripts/terraform` for examples.
- **Local dev without Docker:** Run `cmd/antosara-auth/main.go` (e.g. from VS Code/Cursor). You still need `AWS_REGION` and `AWS_SECRET_ARN` set in the environment and credentials (e.g. `~/.aws` or env) so the app can fetch the secret.
