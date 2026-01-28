# Using antosara-auth as a Private Module

Since this is a private GitHub repository, other Go modules need special configuration to reference it. Here are the recommended approaches:

## Option 1: Replace Directive (Local Development)

If you're working in a monorepo or local development environment, use a `replace` directive in the consuming module's `go.mod`:

```go
module your-other-service

go 1.24.1

require (
    github.com/antosara-dev/antosara-auth v0.0.0
    // ... other dependencies
)

replace github.com/antosara-dev/antosara-auth => ../antosara-auth
// or use absolute path:
// replace github.com/antosara-dev/antosara-auth => C:/Users/vinay/Serious/Antosara/services/antosara-auth
```

**Pros:**
- Simple for local development
- No authentication needed
- Fast builds (no network calls)

**Cons:**
- Only works locally
- Paths are machine-specific
- Not suitable for CI/CD or production

## Option 2: GOPRIVATE with Git Authentication (Recommended for Production)

Configure Go to treat your private module as private and set up Git authentication.

### Step 1: Set GOPRIVATE Environment Variable

```bash
# Windows PowerShell
$env:GOPRIVATE="github.com/antosara-dev"

# Windows CMD
set GOPRIVATE=github.com/antosara-dev

# Linux/Mac
export GOPRIVATE=github.com/antosara-dev
```

Or add to your shell profile (`.bashrc`, `.zshrc`, etc.):
```bash
export GOPRIVATE=github.com/antosara-dev
```

### Step 2: Configure Git Authentication

**Option A: SSH (Recommended)**

1. Ensure your SSH key is added to your GitHub account
2. Configure Git to use SSH for GitHub:
   ```bash
   git config --global url."git@github.com:antosara-dev/".insteadOf "https://github.com/antosara-dev/"
   ```

**Option B: Personal Access Token (PAT)**

1. Create a GitHub Personal Access Token with `repo` scope
2. Configure Git credentials:
   ```bash
   git config --global url."https://YOUR_TOKEN@github.com/antosara-dev/".insteadOf "https://github.com/antosara-dev/"
   ```

   Or use `.netrc` file (Linux/Mac):
   ```
   machine github.com
   login YOUR_GITHUB_USERNAME
   password YOUR_TOKEN
   ```

   Or use Git Credential Manager (Windows):
   ```bash
   git config --global credential.helper manager-core
   ```

### Step 3: Use in Other Modules

In your other module's `go.mod`:
```go
module your-other-service

go 1.24.1

require (
    github.com/antosara-dev/antosara-auth v0.0.0-20240127120000-abcdef123456
    // ... other dependencies
)
```

Then run:
```bash
go get github.com/antosara-dev/antosara-auth@latest
# or specify a version/tag
go get github.com/antosara-dev/antosara-auth@v1.0.0
```

**Pros:**
- Works in CI/CD pipelines
- Supports versioning with Git tags
- Standard Go module workflow

**Cons:**
- Requires authentication setup
- Need to manage tokens/SSH keys

## Option 3: Git Submodules

If you're using Git submodules in a monorepo:

```bash
# In your parent repository
git submodule add https://github.com/antosara-dev/antosara-auth.git services/antosara-auth
```

Then use replace directive:
```go
replace github.com/antosara-dev/antosara-auth => ./services/antosara-auth
```

**Pros:**
- Version control integration
- Works well in monorepos

**Cons:**
- Submodule management overhead
- Still need replace directive

## Option 4: Private Go Module Proxy

For enterprise setups, you can use a private Go module proxy like:
- Athens
- Artifactory
- GitHub Packages (with Go proxy)

This requires setting `GOPROXY` and `GOPRIVATE` appropriately.

## CI/CD Configuration

For GitHub Actions, add this to your workflow:

```yaml
- name: Set up Go
  uses: actions/setup-go@v4
  with:
    go-version: '1.24'

- name: Configure Git for private modules
  run: |
    git config --global url."https://${{ secrets.GITHUB_TOKEN }}@github.com/antosara-dev/".insteadOf "https://github.com/antosara-dev/"

- name: Set GOPRIVATE
  run: echo "GOPRIVATE=github.com/antosara-dev" >> $GITHUB_ENV

- name: Get dependencies
  run: go mod download
```

## Versioning

To use versioned releases, create Git tags:

```bash
# In antosara-auth repository
git tag v1.0.0
git push origin v1.0.0
```

Then reference in other modules:
```go
require github.com/antosara-dev/antosara-auth v1.0.0
```

## Troubleshooting

**Error: "module declares its path as: github.com/antosara-dev/antosara-auth but was required as: antosara-auth"**
- Solution: Update all imports to use the full GitHub path

**Error: "authentication required"**
- Solution: Set up Git authentication (SSH or PAT) and configure GOPRIVATE

**Error: "module not found"**
- Solution: Ensure the repository exists, is accessible, and GOPRIVATE is set correctly
