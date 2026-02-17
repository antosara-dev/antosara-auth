# Generate RSA key pair for JWT signing (RS256)
# PowerShell script for Windows

Write-Host "Generating RSA key pair for JWT signing..." -ForegroundColor Green

# Generate private key
openssl genrsa -out jwt_private_key.pem 2048

# Extract public key
openssl rsa -in jwt_private_key.pem -pubout -out jwt_public_key.pem

Write-Host ""
Write-Host "Keys generated successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Private key (for JWT_PRIVATE_KEY):" -ForegroundColor Yellow
Write-Host "-----------------------------------"
Get-Content jwt_private_key.pem
Write-Host ""
Write-Host "Public key (for JWT_PUBLIC_KEY - use in other services for verification):" -ForegroundColor Yellow
Write-Host "-----------------------------------"
Get-Content jwt_public_key.pem
Write-Host ""
