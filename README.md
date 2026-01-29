
# Antosara Auth

A secure authentication and user management system

**Module Path:** `github.com/antosara-dev/antosara-auth`

> **Note:** This is a private repository. See [MODULE_USAGE.md](./MODULE_USAGE.md) for instructions on how to use this module in other projects.

## Features

- **User Authentication**: Secure signup, login, and email verification
- **Profile Management**: Update user profile and settings

## Environment Configuration

**⚠️ SECURITY WARNING:** Never commit `.env` files or secrets to version control!

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Fill in your actual values in `.env` (see `.env.example` for all available variables)

3. **Important:** The `.env` file is gitignored. Never commit it or any files containing secrets.

### Required Environment Variables

See `.env.example` for a complete template. Key variables:

- **JWT Keys**: Generate RSA keys using `scripts/generate-rsa-keys.sh` (Linux/Mac) or `scripts/generate-rsa-keys.ps1` (Windows)
- **AWS Credentials**: For DynamoDB and SES
- **Email Configuration**: AWS SES SMTP credentials
- **DynamoDB**: Region and optional local endpoint

### Secrets Management Best Practices

- ✅ Use `.env.example` as a template (committed to repo)
- ✅ Keep `.env` local and gitignored
- ✅ Use environment variables or secret management services (AWS Secrets Manager, HashiCorp Vault) in production
- ✅ Rotate secrets regularly
- ❌ Never commit `.env`, `.key`, `.pem`, or any files with secrets
- ❌ Never hardcode secrets in source code
- ❌ Never share secrets via email, chat, or unencrypted channels


## Dev Setup

Setup DynamoDB Local: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html

```
java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -sharedDb
```

Setup Caddy: https://caddyserver.com/docs/quick-starts/reverse-proxy

```
caddy start
```

Run/Debug cmd/antosara-auth/main.go in VS Code/Cursor.

https://localhost/

## Generating RSA Keys for JWT Signing

To use RS256 (asymmetric) JWT signing, generate RSA key pairs:

**Linux/Mac:**
```bash
chmod +x scripts/generate-rsa-keys.sh
./scripts/generate-rsa-keys.sh
```

**Windows (PowerShell):**
```powershell
.\scripts\generate-rsa-keys.ps1
```

**Manual (using OpenSSL):**
```bash
# Generate private key
openssl genrsa -out jwt_private_key.pem 2048

# Extract public key
openssl rsa -in jwt_private_key.pem -pubout -out jwt_public_key.pem
```

Add the private key content to `JWT_PRIVATE_KEY` in your `.env` file. The public key can be shared with other services that need to verify JWTs.
