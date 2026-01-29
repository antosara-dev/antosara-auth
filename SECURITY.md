# Security Guidelines

This document outlines security best practices for the `antosara-auth` service.

## Secrets Management

### Critical Rules

1. **Never commit secrets to version control**
   - `.env` files are gitignored - keep them that way
   - Use `.env.example` as a template (safe to commit)
   - Never commit `.pem`, `.key`, or any files containing secrets

2. **Production Secrets**
   - Use AWS Secrets Manager, HashiCorp Vault, or similar secret management services
   - Never store production secrets in `.env` files
   - Use IAM roles and environment variables in container/serverless environments

3. **Key Rotation**
   - Rotate JWT keys regularly (at least annually, or immediately if compromised)
   - Rotate AWS credentials regularly
   - Use key rotation scripts: `scripts/generate-rsa-keys.sh` or `scripts/generate-rsa-keys.ps1`

### Files to Never Commit

The following patterns are gitignored (see `.gitignore`):

- `.env`, `.env.local`, `.env.*.local`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`
- `secrets/`, `*.secret`
- `.aws/`, `aws-credentials.json`

### If Secrets Are Exposed

If secrets are accidentally committed:

1. **Immediately rotate all exposed secrets**
   - Generate new RSA keys
   - Rotate AWS credentials
   - Update all environment variables

2. **Remove from Git history** (if repository is private):
   ```bash
   git filter-branch --force --index-filter \
     "git rm --cached --ignore-unmatch .env" \
     --prune-empty --tag-name-filter cat -- --all
   ```

3. **Force push** (coordinate with team):
   ```bash
   git push origin --force --all
   ```

4. **Consider the secrets compromised** and treat accordingly

## Security Features

### Implemented Security Measures

- ✅ **JWT Token Revocation**: Revoked tokens stored in DynamoDB with TTL
- ✅ **CSRF Protection**: Session-bound, rotating CSRF tokens
- ✅ **Rate Limiting**: Per-IP rate limiting on authentication endpoints
- ✅ **Password Security**: bcrypt hashing with constant-time comparison
- ✅ **Account Lockout**: Protection against brute force attacks
- ✅ **User Enumeration Prevention**: Generic error messages
- ✅ **Asymmetric JWT (RS256)**: Private key for signing, public keys for verification
- ✅ **Key Rotation Support**: Multiple public keys via JWKS endpoint
- ✅ **Secure Cookies**: HttpOnly, Secure, SameSite attributes
- ✅ **Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- ✅ **Input Validation**: Email format, password complexity, token validation
- ✅ **TTL for Revocations**: Automatic cleanup via DynamoDB TTL

### Security Headers

The service sets the following security headers:

- `Content-Security-Policy`: Restricts resource loading
- `Strict-Transport-Security`: Enforces HTTPS
- `X-Content-Type-Options`: Prevents MIME sniffing
- `X-Frame-Options`: Prevents clickjacking
- `X-XSS-Protection`: XSS protection
- `Referrer-Policy`: Controls referrer information
- `Permissions-Policy`: Restricts browser features

## Production Checklist

Before deploying to production:

- [ ] All secrets are in a secret management service (not `.env`)
- [ ] Tables created using `scripts/create-tables.sh` or `scripts/create-tables.ps1` (auto-create removed)
- [ ] DynamoDB tables created via infrastructure-as-code
- [ ] TTL enabled on `RevokedTokens` table
- [ ] Rate limiting configured appropriately
- [ ] CORS origins restricted to known domains
- [ ] Cookie domain configured for production domain
- [ ] HTTPS enforced (TLS certificates configured)
- [ ] Monitoring and alerting configured
- [ ] Backup strategy in place (DynamoDB PITR)
- [ ] Logging configured (without exposing secrets)
- [ ] Security headers verified
- [ ] JWT keys rotated from development keys

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Contact the maintainers privately
3. Provide details about the vulnerability
4. Allow time for remediation before public disclosure

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
