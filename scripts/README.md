# DynamoDB Table Creation Scripts

This directory contains scripts and infrastructure-as-code templates to create the required DynamoDB tables for the `antosara-auth` service.

## Tables

The service requires three DynamoDB tables:

1. **Users** - Stores user accounts
   - Primary Key: `Email` (String)
   - GSI: `ResetTokenIndex` on `ResetToken` (String)
   - Billing Mode: Pay-per-request

2. **RevokedTokens** - Stores revoked JWT tokens (with TTL)
   - Primary Key: `JTI` (String)
   - TTL Attribute: `ttl` (Number, Unix timestamp)
   - Billing Mode: Pay-per-request

3. **SessionCSRF** - Stores session CSRF tokens
   - Primary Key: `JTI` (String)
   - Billing Mode: Pay-per-request

## Scripts

### AWS CLI Scripts

#### Bash (Linux/macOS/WSL)

```bash
# For local DynamoDB
./scripts/create-tables.sh --endpoint-url http://localhost:8000 --region us-east-1

# For AWS
./scripts/create-tables.sh --region us-east-1
```

#### PowerShell (Windows)

```powershell
# For local DynamoDB
.\scripts\create-tables.ps1 -EndpointUrl http://localhost:8000 -Region us-east-1

# For AWS
.\scripts\create-tables.ps1 -Region us-east-1
```

**Prerequisites:**
- AWS CLI installed and configured
- For AWS: Valid AWS credentials configured (`aws configure` or environment variables)
- For local: Local DynamoDB running (e.g., Docker: `docker run -p 8000:8000 amazon/dynamodb-local`)

### Terraform

**Location:** `scripts/terraform/`

```bash
cd scripts/terraform

# Initialize Terraform
terraform init

# For real AWS (default)
terraform plan
terraform apply

# For DynamoDB Local: set use_local = true to skip STS/credential validation
terraform plan -var="use_local=true"
terraform apply -var="use_local=true"

# Or use a tfvars file (e.g. copy terraform.tfvars.example to terraform.tfvars.local):
terraform plan -var-file=terraform.tfvars.local
terraform apply -var-file=terraform.tfvars.local

# Or set env: TF_VAR_use_local=true
```

**Variables:**
- `aws_region` (default: `us-east-1`)
- `use_local` (default: `false`) — set to `true` for DynamoDB Local; skips STS/credential validation and uses dummy credentials
- `dynamodb_endpoint` (default: `http://localhost:8000`) — used when `use_local = true`

### CloudFormation

**Location:** `scripts/cloudformation/`

```bash
# Create stack
aws cloudformation create-stack \
  --stack-name antosara-auth-tables \
  --template-body file://scripts/cloudformation/dynamodb-tables.yaml \
  --parameters ParameterKey=Environment,ParameterValue=production \
  --region us-east-1

# Update stack
aws cloudformation update-stack \
  --stack-name antosara-auth-tables \
  --template-body file://scripts/cloudformation/dynamodb-tables.yaml \
  --parameters ParameterKey=Environment,ParameterValue=production \
  --region us-east-1
```

**Parameters:**
- `Environment` (default: `production`)

## Production Recommendations

1. **Use Infrastructure-as-Code**: Prefer Terraform or CloudFormation over manual CLI scripts for production
2. **Tables Must Be Created**: Tables are not auto-created. Use the provided scripts or infrastructure-as-code to create tables before starting the service
3. **Backup Strategy**: Enable point-in-time recovery (PITR) for production tables
4. **Monitoring**: Set up CloudWatch alarms for table metrics
5. **Access Control**: Use IAM roles/policies to restrict table access

## Verification

After creating tables, verify they exist:

```bash
# AWS CLI
aws dynamodb list-tables --region us-east-1

# Or describe a specific table
aws dynamodb describe-table --table-name Users --region us-east-1
```

## Troubleshooting

- **Table already exists**: Scripts will skip creation if tables already exist
- **Permission errors**: Ensure AWS credentials have `dynamodb:CreateTable` permission
- **Local DynamoDB**: Ensure local DynamoDB is running and accessible at the endpoint URL
- **TTL not enabled**: For RevokedTokens table, TTL may take a few seconds to enable after table creation
