package oidc

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	dynamoAuthCodesTable     = "OIDCAuthCodes"
	dynamoRefreshTokensTable = "OIDCRefreshTokens"
	dynamoConsentsTable      = "OIDCConsents"
	dynamoTTLAttr            = "ttl"
	dynamoRefreshFamilyIndex = "FamilyIDIndex"
	dynamoRefreshSubIndex    = "SubIndex"
)

type dynamoAuthCodeItem struct {
	CodeHash      string `dynamodbav:"CodeHash"`
	ClientID      string `dynamodbav:"ClientID"`
	RedirectURI   string `dynamodbav:"RedirectURI"`
	CodeChallenge string `dynamodbav:"CodeChallenge"`
	Nonce         string `dynamodbav:"Nonce"`
	Scope         string `dynamodbav:"Scope"`
	Sub           string `dynamodbav:"Sub"`
	SessionJTI    string `dynamodbav:"SessionJTI"`
	AuthTime      int64  `dynamodbav:"AuthTime"`
	ExpiresAt     int64  `dynamodbav:"ExpiresAt"`
}

type dynamoRefreshItem struct {
	TokenHash  string `dynamodbav:"TokenHash"`
	FamilyID   string `dynamodbav:"FamilyID"`
	ClientID   string `dynamodbav:"ClientID"`
	Sub        string `dynamodbav:"Sub"`
	Scope      string `dynamodbav:"Scope"`
	SessionJTI string `dynamodbav:"SessionJTI"`
	AuthTime   int64  `dynamodbav:"AuthTime"`
	ExpiresAt  int64  `dynamodbav:"ExpiresAt"`
	ConsumedAt int64  `dynamodbav:"ConsumedAt,omitempty"`
}

type dynamoConsentItem struct {
	Sub      string `dynamodbav:"Sub"`
	ClientID string `dynamodbav:"ClientID"`
	Scope    string `dynamodbav:"Scope"`
}

// DynamoStores implements OIDC persistence on DynamoDB.
type DynamoStores struct {
	client *dynamodb.Client
}

// NewDynamoStores verifies the OIDC DynamoDB tables exist.
func NewDynamoStores() (*DynamoStores, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	client := dynamodb.NewFromConfig(cfg)
	s := &DynamoStores{client: client}
	for _, table := range []string{dynamoAuthCodesTable, dynamoRefreshTokensTable, dynamoConsentsTable} {
		if err := verifyTableExists(client, table); err != nil {
			return nil, err
		}
	}
	s.enableTTLBestEffort(dynamoAuthCodesTable)
	s.enableTTLBestEffort(dynamoRefreshTokensTable)
	return s, nil
}

func verifyTableExists(client *dynamodb.Client, tableName string) error {
	_, err := client.DescribeTable(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return fmt.Errorf("table %s does not exist or is not accessible: %w. Create tables using scripts/terraform", tableName, err)
	}
	return nil
}

func (s *DynamoStores) enableTTLBestEffort(table string) {
	_, err := s.client.UpdateTimeToLive(context.TODO(), &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(table),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String(dynamoTTLAttr),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		fmt.Printf("Warning: could not enable TTL on %s: %v\n", table, err)
	}
}

func (s *DynamoStores) Put(ctx context.Context, codeHash string, code AuthCode) error {
	item, err := attributevalue.MarshalMap(&dynamoAuthCodeItem{
		CodeHash:      codeHash,
		ClientID:      code.ClientID,
		RedirectURI:   code.RedirectURI,
		CodeChallenge: code.CodeChallenge,
		Nonce:         code.Nonce,
		Scope:         code.Scope,
		Sub:           code.Sub,
		SessionJTI:    code.SessionJTI,
		AuthTime:      code.AuthTime.Unix(),
		ExpiresAt:     code.ExpiresAt.Unix(),
	})
	if err != nil {
		return fmt.Errorf("marshal auth code: %w", err)
	}
	item[dynamoTTLAttr] = &types.AttributeValueMemberN{Value: strconv.FormatInt(code.ExpiresAt.Unix(), 10)}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(dynamoAuthCodesTable),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("store auth code: %w", err)
	}
	return nil
}

func (s *DynamoStores) Consume(ctx context.Context, codeHash string) (*AuthCode, error) {
	out, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(dynamoAuthCodesTable),
		Key: map[string]types.AttributeValue{
			"CodeHash": &types.AttributeValueMemberS{Value: codeHash},
		},
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return nil, fmt.Errorf("consume auth code: %w", err)
	}
	if len(out.Attributes) == 0 {
		return nil, ErrNotFound
	}
	var item dynamoAuthCodeItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &item); err != nil {
		return nil, fmt.Errorf("unmarshal auth code: %w", err)
	}
	if time.Now().Unix() > item.ExpiresAt {
		return nil, ErrNotFound
	}
	return &AuthCode{
		ClientID:      item.ClientID,
		RedirectURI:   item.RedirectURI,
		CodeChallenge: item.CodeChallenge,
		Nonce:         item.Nonce,
		Scope:         item.Scope,
		Sub:           item.Sub,
		SessionJTI:    item.SessionJTI,
		AuthTime:      time.Unix(item.AuthTime, 0),
		ExpiresAt:     time.Unix(item.ExpiresAt, 0),
	}, nil
}

func (s *DynamoStores) putRefresh(ctx context.Context, tokenHash string, rec RefreshRecord) error {
	item, err := attributevalue.MarshalMap(&dynamoRefreshItem{
		TokenHash:  tokenHash,
		FamilyID:   rec.FamilyID,
		ClientID:   rec.ClientID,
		Sub:        rec.Sub,
		Scope:      rec.Scope,
		SessionJTI: rec.SessionJTI,
		AuthTime:   rec.AuthTime.Unix(),
		ExpiresAt:  rec.ExpiresAt.Unix(),
	})
	if err != nil {
		return fmt.Errorf("marshal refresh token: %w", err)
	}
	item[dynamoTTLAttr] = &types.AttributeValueMemberN{Value: strconv.FormatInt(rec.ExpiresAt.Unix(), 10)}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(dynamoRefreshTokensTable),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	return nil
}

func (s *DynamoStores) consumeRefresh(ctx context.Context, tokenHash string) (*RefreshRecord, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dynamoRefreshTokensTable),
		Key: map[string]types.AttributeValue{
			"TokenHash": &types.AttributeValueMemberS{Value: tokenHash},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("lookup refresh token: %w", err)
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	var item dynamoRefreshItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, fmt.Errorf("unmarshal refresh token: %w", err)
	}
	rec := RefreshRecord{
		FamilyID:   item.FamilyID,
		ClientID:   item.ClientID,
		Sub:        item.Sub,
		Scope:      item.Scope,
		SessionJTI: item.SessionJTI,
		AuthTime:   time.Unix(item.AuthTime, 0),
		ExpiresAt:  time.Unix(item.ExpiresAt, 0),
		Consumed:   item.ConsumedAt > 0,
	}
	if time.Now().After(rec.ExpiresAt) {
		return nil, ErrNotFound
	}
	if rec.Consumed {
		return &rec, ErrReuseDetected
	}

	now := time.Now().Unix()
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(dynamoRefreshTokensTable),
		Key: map[string]types.AttributeValue{
			"TokenHash": &types.AttributeValueMemberS{Value: tokenHash},
		},
		ConditionExpression: aws.String("attribute_not_exists(ConsumedAt) OR ConsumedAt = :zero"),
		UpdateExpression:    aws.String("SET ConsumedAt = :now"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":  &types.AttributeValueMemberN{Value: strconv.FormatInt(now, 10)},
			":zero": &types.AttributeValueMemberN{Value: "0"},
		},
	})
	if err != nil {
		return &rec, ErrReuseDetected
	}
	return &rec, nil
}

func (s *DynamoStores) RevokeFamily(ctx context.Context, familyID string) error {
	return s.deleteByIndex(ctx, dynamoRefreshFamilyIndex, "FamilyID", familyID)
}

func (s *DynamoStores) RevokeBySub(ctx context.Context, sub string) error {
	return s.deleteByIndex(ctx, dynamoRefreshSubIndex, "Sub", sub)
}

func (s *DynamoStores) deleteByIndex(ctx context.Context, index, attr, value string) error {
	paginator := dynamodb.NewQueryPaginator(s.client, &dynamodb.QueryInput{
		TableName:              aws.String(dynamoRefreshTokensTable),
		IndexName:              aws.String(index),
		KeyConditionExpression: aws.String(fmt.Sprintf("%s = :v", attr)),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":v": &types.AttributeValueMemberS{Value: value},
		},
		ProjectionExpression: aws.String("TokenHash"),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("query refresh tokens: %w", err)
		}
		for _, item := range page.Items {
			hashAttr, ok := item["TokenHash"].(*types.AttributeValueMemberS)
			if !ok {
				continue
			}
			_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName: aws.String(dynamoRefreshTokensTable),
				Key: map[string]types.AttributeValue{
					"TokenHash": &types.AttributeValueMemberS{Value: hashAttr.Value},
				},
			})
			if err != nil {
				return fmt.Errorf("delete refresh token: %w", err)
			}
		}
	}
	return nil
}

func (s *DynamoStores) GetConsent(ctx context.Context, sub, clientID string) (*Consent, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(dynamoConsentsTable),
		Key: map[string]types.AttributeValue{
			"Sub":      &types.AttributeValueMemberS{Value: sub},
			"ClientID": &types.AttributeValueMemberS{Value: clientID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("get consent: %w", err)
	}
	if out.Item == nil {
		return nil, ErrNotFound
	}
	var item dynamoConsentItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return nil, fmt.Errorf("unmarshal consent: %w", err)
	}
	return &Consent{Sub: item.Sub, ClientID: item.ClientID, Scope: item.Scope}, nil
}

func (s *DynamoStores) PutConsent(ctx context.Context, c Consent) error {
	item, err := attributevalue.MarshalMap(&dynamoConsentItem{
		Sub:      c.Sub,
		ClientID: c.ClientID,
		Scope:    c.Scope,
	})
	if err != nil {
		return fmt.Errorf("marshal consent: %w", err)
	}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(dynamoConsentsTable),
		Item:      item,
	})
	if err != nil {
		return fmt.Errorf("put consent: %w", err)
	}
	return nil
}

type dynamoCodeStore struct{ s *DynamoStores }
type dynamoRefreshStore struct{ s *DynamoStores }
type dynamoConsentStore struct{ s *DynamoStores }

func (c dynamoCodeStore) Put(ctx context.Context, codeHash string, code AuthCode) error {
	return c.s.Put(ctx, codeHash, code)
}
func (c dynamoCodeStore) Consume(ctx context.Context, codeHash string) (*AuthCode, error) {
	return c.s.Consume(ctx, codeHash)
}

func (c dynamoRefreshStore) Put(ctx context.Context, tokenHash string, rec RefreshRecord) error {
	return c.s.putRefresh(ctx, tokenHash, rec)
}
func (c dynamoRefreshStore) Consume(ctx context.Context, tokenHash string) (*RefreshRecord, error) {
	return c.s.consumeRefresh(ctx, tokenHash)
}
func (c dynamoRefreshStore) RevokeFamily(ctx context.Context, familyID string) error {
	return c.s.RevokeFamily(ctx, familyID)
}
func (c dynamoRefreshStore) RevokeBySub(ctx context.Context, sub string) error {
	return c.s.RevokeBySub(ctx, sub)
}

func (c dynamoConsentStore) Get(ctx context.Context, sub, clientID string) (*Consent, error) {
	return c.s.GetConsent(ctx, sub, clientID)
}
func (c dynamoConsentStore) Put(ctx context.Context, cons Consent) error {
	return c.s.PutConsent(ctx, cons)
}

// AsStores exposes DynamoStores as the three OIDC store interfaces.
func (s *DynamoStores) AsStores() Stores {
	return Stores{
		Codes:    dynamoCodeStore{s},
		Refresh:  dynamoRefreshStore{s},
		Consents: dynamoConsentStore{s},
	}
}
