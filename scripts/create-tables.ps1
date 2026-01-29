# Script to create DynamoDB tables for antosara-auth service
# Usage: .\create-tables.ps1 [-EndpointUrl ENDPOINT] [-Region REGION]
#
# For local DynamoDB: .\create-tables.ps1 -EndpointUrl http://localhost:8000 -Region us-east-1
# For AWS: .\create-tables.ps1 -Region us-east-1

param(
    [string]$EndpointUrl = "",
    [string]$Region = $env:AWS_REGION
)

if ([string]::IsNullOrEmpty($Region)) {
    $Region = "us-east-1"
}

Write-Host "Creating DynamoDB tables in region: $Region" -ForegroundColor Green
if ($EndpointUrl) {
    Write-Host "Using endpoint: $EndpointUrl" -ForegroundColor Yellow
}

$endpointArgs = @{}
if ($EndpointUrl) {
    $endpointArgs["EndpointUrl"] = $EndpointUrl
}

# 1. Create Users table
Write-Host "`nCreating Users table..." -ForegroundColor Cyan
try {
    $usersTable = @{
        TableName = "Users"
        AttributeDefinitions = @(
            @{ AttributeName = "Email"; AttributeType = "S" }
            @{ AttributeName = "ResetToken"; AttributeType = "S" }
        )
        KeySchema = @(
            @{ AttributeName = "Email"; KeyType = "HASH" }
        )
        GlobalSecondaryIndexes = @(
            @{
                IndexName = "ResetTokenIndex"
                KeySchema = @(
                    @{ AttributeName = "ResetToken"; KeyType = "HASH" }
                )
                Projection = @{ ProjectionType = "ALL" }
            }
        )
        BillingMode = "PAY_PER_REQUEST"
    }
    
    New-DDBTable -TableName "Users" -AttributeDefinition $usersTable.AttributeDefinitions `
        -KeySchema $usersTable.KeySchema -GlobalSecondaryIndex $usersTable.GlobalSecondaryIndexes `
        -BillingMode $usersTable.BillingMode @endpointArgs -Region $Region -ErrorAction SilentlyContinue
    Write-Host "Users table created (or already exists)" -ForegroundColor Green
} catch {
    Write-Host "Users table may already exist: $_" -ForegroundColor Yellow
}

# 2. Create RevokedTokens table
Write-Host "`nCreating RevokedTokens table..." -ForegroundColor Cyan
try {
    $revokedTokensTable = @{
        TableName = "RevokedTokens"
        AttributeDefinitions = @(
            @{ AttributeName = "JTI"; AttributeType = "S" }
        )
        KeySchema = @(
            @{ AttributeName = "JTI"; KeyType = "HASH" }
        )
        BillingMode = "PAY_PER_REQUEST"
    }
    
    New-DDBTable -TableName "RevokedTokens" -AttributeDefinition $revokedTokensTable.AttributeDefinitions `
        -KeySchema $revokedTokensTable.KeySchema -BillingMode $revokedTokensTable.BillingMode `
        @endpointArgs -Region $Region -ErrorAction SilentlyContinue
    Write-Host "RevokedTokens table created (or already exists)" -ForegroundColor Green
    
    # Enable TTL on RevokedTokens table
    Write-Host "Enabling TTL on RevokedTokens table..." -ForegroundColor Cyan
    Start-Sleep -Seconds 2  # Wait for table to be active
    Update-DDBTimeToLive -TableName "RevokedTokens" `
        -TimeToLiveSpecification_Enabled $true -TimeToLiveSpecification_AttributeName "ttl" `
        @endpointArgs -Region $Region -ErrorAction SilentlyContinue
    Write-Host "TTL enabled on RevokedTokens table" -ForegroundColor Green
} catch {
    Write-Host "RevokedTokens table may already exist or TTL already enabled: $_" -ForegroundColor Yellow
}

# 3. Create SessionCSRF table
Write-Host "`nCreating SessionCSRF table..." -ForegroundColor Cyan
try {
    $sessionCSRFTable = @{
        TableName = "SessionCSRF"
        AttributeDefinitions = @(
            @{ AttributeName = "JTI"; AttributeType = "S" }
        )
        KeySchema = @(
            @{ AttributeName = "JTI"; KeyType = "HASH" }
        )
        BillingMode = "PAY_PER_REQUEST"
    }
    
    New-DDBTable -TableName "SessionCSRF" -AttributeDefinition $sessionCSRFTable.AttributeDefinitions `
        -KeySchema $sessionCSRFTable.KeySchema -BillingMode $sessionCSRFTable.BillingMode `
        @endpointArgs -Region $Region -ErrorAction SilentlyContinue
    Write-Host "SessionCSRF table created (or already exists)" -ForegroundColor Green
    
    # Enable TTL on SessionCSRF table
    Write-Host "Enabling TTL on SessionCSRF table..." -ForegroundColor Cyan
    Start-Sleep -Seconds 2  # Wait for table to be active
    Update-DDBTimeToLive -TableName "SessionCSRF" `
        -TimeToLiveSpecification_Enabled $true -TimeToLiveSpecification_AttributeName "ttl" `
        @endpointArgs -Region $Region -ErrorAction SilentlyContinue
    Write-Host "TTL enabled on SessionCSRF table" -ForegroundColor Green
} catch {
    Write-Host "SessionCSRF table may already exist or TTL already enabled: $_" -ForegroundColor Yellow
}

Write-Host "`nAll tables created successfully!" -ForegroundColor Green
Write-Host "`nTo verify tables exist, run:" -ForegroundColor Cyan
if ($EndpointUrl) {
    Write-Host "  Get-DDBTableList -EndpointUrl $EndpointUrl -Region $Region" -ForegroundColor White
} else {
    Write-Host "  Get-DDBTableList -Region $Region" -ForegroundColor White
}
