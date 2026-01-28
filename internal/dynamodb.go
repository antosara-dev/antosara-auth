package internal

import (
	"antosara-auth/pkg"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	usersTableName           = "Users"
	revokedTokensTableName   = "RevokedTokens"
)

// DynamoDBUserRepository implements UserRepository using DynamoDB
type DynamoDBUserRepository struct {
	client    *dynamodb.Client
	tableName string
}

// NewDynamoDBUserRepository creates a new DynamoDB user repository
func NewDynamoDBUserRepository() (*DynamoDBUserRepository, error) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	// Create DynamoDB client
	client := dynamodb.NewFromConfig(cfg)

	// Create repository
	repo := &DynamoDBUserRepository{
		client:    client,
		tableName: usersTableName,
	}

	// Create table if it doesn't exist
	if err := repo.createTableIfNotExists(); err != nil {
		return nil, err
	}

	return repo, nil
}

// createTableIfNotExists creates the DynamoDB table if it doesn't exist
func (r *DynamoDBUserRepository) createTableIfNotExists() error {
	// Check if table exists
	_, err := r.client.DescribeTable(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(r.tableName),
	})
	if err == nil {
		// Table exists
		return nil
	}

	// Create table
	_, err = r.client.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(r.tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("Email"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("Email"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	return nil
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
	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	user.VerificationCode = code

	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %v", err)
	}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(r.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(Email)"),
	})
	if err != nil {
		var conditionCheckFailedErr *types.ConditionalCheckFailedException
		if errors.As(err, &conditionCheckFailedErr) {
			return fmt.Errorf("user with email %s already exists", user.Email)
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
	// Use scan operation since reset token is not a primary key
	result, err := r.client.Scan(ctx, &dynamodb.ScanInput{
		TableName:        aws.String(r.tableName),
		FilterExpression: aws.String("ResetToken = :token"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":token": &types.AttributeValueMemberS{Value: token},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan for user: %v", err)
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

// NewDynamoDBTokenRevocationRepository creates a new DynamoDB token revocation repository
func NewDynamoDBTokenRevocationRepository() (*DynamoDBTokenRevocationRepository, error) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	// Create DynamoDB client
	client := dynamodb.NewFromConfig(cfg)

	// Create repository
	repo := &DynamoDBTokenRevocationRepository{
		client:    client,
		tableName: revokedTokensTableName,
	}

	// Create table if it doesn't exist
	if err := repo.createTableIfNotExists(); err != nil {
		return nil, err
	}

	return repo, nil
}

// createTableIfNotExists creates the DynamoDB table if it doesn't exist
func (r *DynamoDBTokenRevocationRepository) createTableIfNotExists() error {
	// Check if table exists
	_, err := r.client.DescribeTable(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(r.tableName),
	})
	if err == nil {
		// Table exists
		return nil
	}

	// Create table
	_, err = r.client.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(r.tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("JTI"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("JTI"),
				KeyType:       types.KeyTypeHash,
			},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		return fmt.Errorf("failed to create revoked tokens table: %v", err)
	}

	return nil
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

// CleanupExpiredRevocations removes expired token revocations
func (r *DynamoDBTokenRevocationRepository) CleanupExpiredRevocations(ctx context.Context) error {
	// Scan for all revoked tokens
	result, err := r.client.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(r.tableName),
	})
	if err != nil {
		return fmt.Errorf("failed to scan revoked tokens: %v", err)
	}

	now := time.Now()
	for _, item := range result.Items {
		var revokedToken pkg.RevokedToken
		if err := attributevalue.UnmarshalMap(item, &revokedToken); err != nil {
			continue
		}

		// If token has expired, delete it
		if now.After(revokedToken.ExpiresAt) {
			_, err := r.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName: aws.String(r.tableName),
				Key: map[string]types.AttributeValue{
					"JTI": &types.AttributeValueMemberS{Value: revokedToken.JTI},
				},
			})
			if err != nil {
				// Log error but continue cleanup
				fmt.Printf("Failed to delete expired revocation for JTI %s: %v\n", revokedToken.JTI, err)
			}
		}
	}

	return nil
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
