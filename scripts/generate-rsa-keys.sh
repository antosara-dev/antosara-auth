#!/bin/bash
# Generate RSA key pair for JWT signing (RS256)
# This script generates a 2048-bit RSA private key and extracts the public key

echo "Generating RSA key pair for JWT signing..."

# Generate private key
openssl genrsa -out jwt_private_key.pem 2048

# Extract public key
openssl rsa -in jwt_private_key.pem -pubout -out jwt_public_key.pem

echo ""
echo "Keys generated successfully!"
echo ""
echo "Private key (for JWT_PRIVATE_KEY):"
echo "-----------------------------------"
cat jwt_private_key.pem
echo ""
echo "Public key (for JWT_PUBLIC_KEY - use in other services for verification):"
echo "-----------------------------------"
cat jwt_public_key.pem
echo ""
echo "Add JWT_PRIVATE_KEY to your .env file with the private key content"
echo "Add JWT_PUBLIC_KEY to other services that need to verify JWTs"
