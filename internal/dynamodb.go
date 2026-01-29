package internal

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/antosara-dev/antosara-auth/pkg"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	usersTableName         = "Users"
	revokedTokensTableName = "RevokedTokens"
	sessionCSRFTablename   = "SessionCSRF"
	revokedTokensTTLAttr   = "ttl" // DynamoDB TTL attribute name (unix seconds)
	sessionCSRFTTLAttr     = "ttl" // DynamoDB TTL attribute name for SessionCSRF (unix seconds)
)

// verifyTableExists checks if a table exists without creating it
// Tables must be created using scripts/create-tables.sh or scripts/create-tables.ps1
func verifyTableExists(client *dynamodb.Client, tableName string) error {
	_, err := client.DescribeTable(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return fmt.Errorf("table %s does not exist or is not accessible: %v. Create tables using scripts/create-tables.sh or scripts/create-tables.ps1", tableName, err)
	}
	return nil
}

// getDynamoDBClient creates a DynamoDB client with support for local DynamoDB
func getDynamoDBClient() (*dynamodb.Client, error) {
	// If DYNAMODB_ENDPOINT is set, use it for local DynamoDB
	endpoint := os.Getenv("DYNAMODB_ENDPOINT")

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(getAWSRegion()),
	}

	if endpoint != "" {
		// For local DynamoDB, use dummy credentials
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", "")))
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	// Configure DynamoDB client options
	clientOpts := []func(*dynamodb.Options){}
	if endpoint != "" {
		// Use EndpointResolverFromURL to point to local DynamoDB
		clientOpts = append(clientOpts, dynamodb.WithEndpointResolver(dynamodb.EndpointResolverFromURL(endpoint)))
	}

	return dynamodb.NewFromConfig(cfg, clientOpts...), nil
}

// getAWSRegion returns the AWS region from environment or defaults to us-east-1
func getAWSRegion() string {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		return "us-east-1"
	}
	return region
}

// DynamoDBSessionCSRFRepository implements SessionCSRFRepository using DynamoDB
type DynamoDBSessionCSRFRepository struct {
	client    *dynamodb.Client
	tableName string
}

func (r *DynamoDBSessionCSRFRepository) enableTTLBestEffort() {
	// TTL is best-effort: DynamoDB Local may not support it, and AWS may return
	// validation errors if already enabled/disabled. We never want to fail startup.
	_, err := r.client.UpdateTimeToLive(context.TODO(), &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(r.tableName),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String(sessionCSRFTTLAttr),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		// Don't fail startup; just log.
		fmt.Printf("Warning: could not enable TTL on %s: %v\n", r.tableName, err)
	}
}

func NewDynamoDBSessionCSRFRepository() (*DynamoDBSessionCSRFRepository, error) {
	client, err := getDynamoDBClient()
	if err != nil {
		return nil, err
	}

	repo := &DynamoDBSessionCSRFRepository{
		client:    client,
		tableName: sessionCSRFTablename,
	}

	// Verify table exists (tables must be created using scripts/create-tables.sh or scripts/create-tables.ps1)
	if err := verifyTableExists(client, repo.tableName); err != nil {
		return nil, err
	}

	// Try to enable TTL (best-effort, won't fail if already enabled)
	repo.enableTTLBestEffort()

	return repo, nil
}

func (r *DynamoDBSessionCSRFRepository) Put(ctx context.Context, jti string, token string, expiresAt time.Time) error {
	item, err := attributevalue.MarshalMap(&pkg.SessionCSRF{
		JTI:       jti,
		Token:     token,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal session csrf: %v", err)
	}

	// Add TTL attribute (unix seconds). DynamoDB will delete items automatically after expiry.
	item[sessionCSRFTTLAttr] = &types.AttributeValueMemberN{Value: strconv.FormatInt(expiresAt.Unix(), 10)}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("failed to store session csrf: %v", err)
	}
	return nil
}

func (r *DynamoDBSessionCSRFRepository) Get(ctx context.Context, jti string) (*pkg.SessionCSRF, error) {
	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"JTI": &types.AttributeValueMemberS{Value: jti},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get session csrf: %v", err)
	}
	if result.Item == nil {
		return nil, pkg.ErrUserNotFound
	}
	var out pkg.SessionCSRF
	if err := attributevalue.UnmarshalMap(result.Item, &out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session csrf: %v", err)
	}
	return &out, nil
}

func (r *DynamoDBSessionCSRFRepository) Delete(ctx context.Context, jti string) error {
	_, err := r.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"JTI": &types.AttributeValueMemberS{Value: jti},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete session csrf: %v", err)
	}
	return nil
}

// DynamoDBUserRepository implements UserRepository using DynamoDB
type DynamoDBUserRepository struct {
	client    *dynamodb.Client
	tableName string
}

// NewDynamoDBUserRepository creates a new DynamoDB user repository
func NewDynamoDBUserRepository() (*DynamoDBUserRepository, error) {
	// Create DynamoDB client
	client, err := getDynamoDBClient()
	if err != nil {
		return nil, err
	}

	// Create repository
	repo := &DynamoDBUserRepository{
		client:    client,
		tableName: usersTableName,
	}

	// Verify table exists (tables must be created using scripts/create-tables.sh or scripts/create-tables.ps1)
	if err := verifyTableExists(client, repo.tableName); err != nil {
		return nil, err
	}

	return repo, nil
}

// GetUserByEmail retrieves a user by their email
func (r *DynamoDBUserRepository) GetUserByEmail(ctx context.Context, email string) (*pkg.User, error) {
	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"Email": &types.AttributeValueMemberS{Value: email},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %v", err)
	}

	if result.Item == nil {
		return nil, pkg.ErrUserNotFound
	}

	var user pkg.User
	err = attributevalue.UnmarshalMap(result.Item, &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %v", err)
	}

	return &user, nil
}

// CreateUser creates a new user
func (r *DynamoDBUserRepository) CreateUser(ctx context.Context, user *pkg.User) error {
	// Set Verified to false by default
	user.Verified = false

	// Generate a random 6-digit verification code
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return fmt.Errorf("failed to generate verification code: %v", err)
	}
	code := fmt.Sprintf("%06d", n.Int64())
	user.VerificationCode = code
	// Default verification-code expiry: 24 hours (override with VERIFICATION_CODE_EXPIRY_MINUTES)
	expiryMinutes := 24 * 60
	if s := os.Getenv("VERIFICATION_CODE_EXPIRY_MINUTES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			expiryMinutes = v
		}
	}
	user.VerificationCodeExpiry = time.Now().Add(time.Duration(expiryMinutes) * time.Minute)

	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %v", err)
	}

	// Remove ResetToken from item if it's empty (DynamoDB doesn't allow empty strings for GSI keys)
	if resetTokenVal, ok := item["ResetToken"]; ok {
		if strVal, ok := resetTokenVal.(*types.AttributeValueMemberS); ok && strVal.Value == "" {
			delete(item, "ResetToken")
		}
	}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(r.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(Email)"),
	})
	if err != nil {
		var conditionCheckFailedErr *types.ConditionalCheckFailedException
		if errors.As(err, &conditionCheckFailedErr) {
			// Don't include email in error message (prevents information leakage)
			return fmt.Errorf("user already exists")
		}
		return fmt.Errorf("failed to create user: %v", err)
	}

	// Send verification email in a goroutine
	go func(email, code string) {
		_ = sendVerificationEmail(email, code)
	}(user.Email, user.VerificationCode)

	return nil
}

// UpdateUser updates an existing user
func (r *DynamoDBUserRepository) UpdateUser(ctx context.Context, user *pkg.User) error {
	// Skip password hashing for updates
	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %v", err)
	}

	// Remove ResetToken from item if it's empty (DynamoDB doesn't allow empty strings for GSI keys)
	if resetTokenVal, ok := item["ResetToken"]; ok {
		if strVal, ok := resetTokenVal.(*types.AttributeValueMemberS); ok && strVal.Value == "" {
			delete(item, "ResetToken")
		}
	}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(r.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_exists(Email)"),
	})
	if err != nil {
		var conditionCheckFailedErr *types.ConditionalCheckFailedException
		if errors.As(err, &conditionCheckFailedErr) {
			return pkg.ErrUserNotFound
		}
		return fmt.Errorf("failed to update user: %v", err)
	}

	return nil
}

// DeleteUser deletes a user
func (r *DynamoDBUserRepository) DeleteUser(ctx context.Context, email string) error {
	_, err := r.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"Email": &types.AttributeValueMemberS{Value: email},
		},
		ConditionExpression: aws.String("attribute_exists(Email)"),
	})
	if err != nil {
		var conditionCheckFailedErr *types.ConditionalCheckFailedException
		if errors.As(err, &conditionCheckFailedErr) {
			return pkg.ErrUserNotFound
		}
		return fmt.Errorf("failed to delete user: %v", err)
	}

	return nil
}

// GetUserByResetToken retrieves a user by their reset token
func (r *DynamoDBUserRepository) GetUserByResetToken(ctx context.Context, token string) (*pkg.User, error) {
	result, err := r.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.tableName),
		IndexName:              aws.String("ResetTokenIndex"),
		KeyConditionExpression: aws.String("ResetToken = :token"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":token": &types.AttributeValueMemberS{Value: token},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query user by reset token: %v", err)
	}

	if len(result.Items) == 0 {
		return nil, pkg.ErrUserNotFound
	}

	// Should only be one user with this reset token
	var user pkg.User
	err = attributevalue.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %v", err)
	}

	return &user, nil
}

// DynamoDBTokenRevocationRepository implements TokenRevocationRepository using DynamoDB
type DynamoDBTokenRevocationRepository struct {
	client    *dynamodb.Client
	tableName string
}

func (r *DynamoDBTokenRevocationRepository) enableTTLBestEffort() {
	// TTL is best-effort: DynamoDB Local may not support it, and AWS may return
	// validation errors if already enabled/disabled. We never want to fail startup.
	_, err := r.client.UpdateTimeToLive(context.TODO(), &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(r.tableName),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String(revokedTokensTTLAttr),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		// Don't fail startup; just log.
		fmt.Printf("Warning: could not enable TTL on %s: %v\n", r.tableName, err)
	}
}

// NewDynamoDBTokenRevocationRepository creates a new DynamoDB token revocation repository
func NewDynamoDBTokenRevocationRepository() (*DynamoDBTokenRevocationRepository, error) {
	// Create DynamoDB client
	client, err := getDynamoDBClient()
	if err != nil {
		return nil, err
	}

	// Create repository
	repo := &DynamoDBTokenRevocationRepository{
		client:    client,
		tableName: revokedTokensTableName,
	}

	// Verify table exists (tables must be created using scripts/create-tables.sh or scripts/create-tables.ps1)
	if err := verifyTableExists(client, repo.tableName); err != nil {
		return nil, err
	}

	// Try to enable TTL (best-effort, won't fail if already enabled)
	repo.enableTTLBestEffort()

	return repo, nil
}

// RevokeToken marks a token as revoked
func (r *DynamoDBTokenRevocationRepository) RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error {
	revokedToken := &pkg.RevokedToken{
		JTI:       jti,
		RevokedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	item, err := attributevalue.MarshalMap(revokedToken)
	if err != nil {
		return fmt.Errorf("failed to marshal revoked token: %v", err)
	}

	// Add TTL attribute (unix seconds). DynamoDB will delete items automatically after expiry.
	item[revokedTokensTTLAttr] = &types.AttributeValueMemberN{Value: strconv.FormatInt(expiresAt.Unix(), 10)}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(r.tableName),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("failed to revoke token: %v", err)
	}

	return nil
}

// IsTokenRevoked checks if a token is revoked
func (r *DynamoDBTokenRevocationRepository) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	result, err := r.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(r.tableName),
		Key: map[string]types.AttributeValue{
			"JTI": &types.AttributeValueMemberS{Value: jti},
		},
	})
	if err != nil {
		return false, fmt.Errorf("failed to check token revocation: %v", err)
	}

	// If item exists, token is revoked
	return result.Item != nil, nil
}

// DynamoDBResolutionRepository implements ResolutionRepository using DynamoDB
type DynamoDBResolutionRepository struct {
	client    *dynamodb.Client
	tableName string
}

func (r *DynamoDBResolutionRepository) createTableIfNotExists() error {
	_, err := r.client.DescribeTable(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(r.tableName),
	})
	if err == nil {
		return nil
	}

	_, err = r.client.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(r.tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("userEmail"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       types.KeyTypeHash,
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String("UserEmailIndex"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("userEmail"),
						KeyType:       types.KeyTypeHash,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll,
				},
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		return fmt.Errorf("failed to create resolutions table: %v", err)
	}

	return nil
}
