#!/bin/bash
# Script to create DynamoDB tables for antosara-auth service
# Usage: ./create-tables.sh [--endpoint-url ENDPOINT] [--region REGION]
#
# For local DynamoDB: ./create-tables.sh --endpoint-url http://localhost:8000 --region us-east-1
# For AWS: ./create-tables.sh --region us-east-1

set -e

ENDPOINT_ARG=""
REGION="${AWS_REGION:-us-east-1}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --endpoint-url)
            ENDPOINT_ARG="--endpoint-url $2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--endpoint-url ENDPOINT] [--region REGION]"
            exit 1
            ;;
    esac
done

echo "Creating DynamoDB tables in region: $REGION"
if [ -n "$ENDPOINT_ARG" ]; then
    echo "Using endpoint: $ENDPOINT_ARG"
fi

# 1. Create Users table
echo "Creating Users table..."
aws dynamodb create-table $ENDPOINT_ARG \
    --region "$REGION" \
    --table-name Users \
    --attribute-definitions \
        AttributeName=Email,AttributeType=S \
        AttributeName=ResetToken,AttributeType=S \
    --key-schema \
        AttributeName=Email,KeyType=HASH \
    --global-secondary-indexes \
        "[{
            \"IndexName\": \"ResetTokenIndex\",
            \"KeySchema\": [{\"AttributeName\": \"ResetToken\", \"KeyType\": \"HASH\"}],
            \"Projection\": {\"ProjectionType\": \"ALL\"}
        }]" \
    --billing-mode PAY_PER_REQUEST \
    --no-cli-pager || echo "Users table may already exist"

# 2. Create RevokedTokens table
echo "Creating RevokedTokens table..."
aws dynamodb create-table $ENDPOINT_ARG \
    --region "$REGION" \
    --table-name RevokedTokens \
    --attribute-definitions \
        AttributeName=JTI,AttributeType=S \
    --key-schema \
        AttributeName=JTI,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --no-cli-pager || echo "RevokedTokens table may already exist"

# Enable TTL on RevokedTokens table
echo "Enabling TTL on RevokedTokens table..."
aws dynamodb update-time-to-live $ENDPOINT_ARG \
    --region "$REGION" \
    --table-name RevokedTokens \
    --time-to-live-specification Enabled=true,AttributeName=ttl \
    --no-cli-pager || echo "TTL may already be enabled or table doesn't exist yet"

# 3. Create SessionCSRF table
echo "Creating SessionCSRF table..."
aws dynamodb create-table $ENDPOINT_ARG \
    --region "$REGION" \
    --table-name SessionCSRF \
    --attribute-definitions \
        AttributeName=JTI,AttributeType=S \
    --key-schema \
        AttributeName=JTI,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --no-cli-pager || echo "SessionCSRF table may already exist"

# Enable TTL on SessionCSRF table
echo "Enabling TTL on SessionCSRF table..."
aws dynamodb update-time-to-live $ENDPOINT_ARG \
    --region "$REGION" \
    --table-name SessionCSRF \
    --time-to-live-specification Enabled=true,AttributeName=ttl \
    --no-cli-pager || echo "TTL may already be enabled or table doesn't exist yet"

echo ""
echo "All tables created successfully!"
echo ""
echo "To verify tables exist, run:"
echo "  aws dynamodb list-tables $ENDPOINT_ARG --region $REGION"
