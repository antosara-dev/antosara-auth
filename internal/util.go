package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/joho/godotenv"
)

// LoadEnv loads configuration into the process environment.
// A local .env file is loaded first if present (existing process env wins over
// .env). If AWS_SECRET_ARN or AWS_SECRET_NAME is set after that, the secret is
// fetched from AWS Secrets Manager and overwrites matching variables.
func LoadEnv() error {
	if err := godotenv.Load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load .env: %w", err)
		}
	} else {
		log.Println("Loaded environment from .env")
	}

	secretID := os.Getenv("AWS_SECRET_ARN")
	if secretID == "" {
		secretID = os.Getenv("AWS_SECRET_NAME")
	}
	if secretID != "" {
		if err := loadSecretIntoEnv(secretID); err != nil {
			return fmt.Errorf("load secret into env: %w", err)
		}
		log.Println("Loaded environment from AWS Secrets Manager")
	} else {
		log.Println("Using process environment (AWS Secrets Manager not configured)")
	}
	unescapeJWTKeys()
	return nil
}

// envEnabled reports whether an env var is truthy. Unset or empty is false.
// Accepted true values: 1, true, yes, on (case-insensitive).
func envEnabled(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// unescapeJWTKeys turns literal \n sequences in PEM env vars into real newlines
// so keys work the same whether they come from Secrets Manager JSON or process env.
func unescapeJWTKeys() {
	for _, k := range []string{"JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY", "JWT_PUBLIC_KEYS"} {
		if v := os.Getenv(k); v != "" {
			_ = os.Setenv(k, strings.ReplaceAll(v, `\n`, "\n"))
		}
	}
}

// loadSecretIntoEnv fetches the secret from AWS Secrets Manager and sets each
// key-value pair in the secret (JSON object) as an environment variable.
func loadSecretIntoEnv(secretID string) error {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-west-2"
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	client := secretsmanager.NewFromConfig(cfg)
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretID,
	})
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}
	if out.SecretString == nil || *out.SecretString == "" {
		return fmt.Errorf("secret value is empty")
	}
	var kv map[string]interface{}
	if err := json.Unmarshal([]byte(*out.SecretString), &kv); err != nil {
		return fmt.Errorf("secret is not valid JSON: %w", err)
	}
	for k, v := range kv {
		if k == "" {
			continue
		}
		val := fmt.Sprint(v)
		if err := os.Setenv(k, val); err != nil {
			return fmt.Errorf("setenv %s: %w", k, err)
		}
	}
	return nil
}

// sendVerificationEmail sends a verification code to the user's email using AWS SES
func sendVerificationEmail(toEmail, code string) error {
	subject := "Your Verification Code"
	body := "Your verification code is: " + code

	fromEmail := os.Getenv("EMAIL_SENDER")
	auth := smtp.PlainAuth("", os.Getenv("EMAIL_HOST_USER"), os.Getenv("EMAIL_HOST_PASSWORD"), os.Getenv("EMAIL_HOST"))
	err := smtp.SendMail(os.Getenv("EMAIL_HOST")+":587", auth, fromEmail, []string{toEmail}, []byte("To: "+toEmail+"\r\nSubject: "+subject+"\r\n\r\n"+body))
	if err != nil {
		// Don't log email addresses (PII protection)
		log.Printf("Could not send verification email: %v", err)
		return err
	}
	// Don't log email addresses (PII protection)
	log.Printf("Verification email sent successfully")
	return nil
}

// sendPasswordResetEmail sends a password reset link to the user's email
func sendPasswordResetEmail(toEmail, resetToken string) error {
	subject := "Reset Your Password"
	body := "Somebody requested a password reset for your account. If you did not request this, please ignore this email.\n\n" +
		"Click the following link to reset your password:\n\n" +
		os.Getenv("PASSWORD_RESET_URL") + "?token=" + resetToken + "\n\n" +
		//"https://" + os.Getenv("HOST_NAME") + "/web/new-password.html?token=" + resetToken + "\n\n" +
		"If you didn't request this, please ignore this email."

	fromEmail := os.Getenv("EMAIL_SENDER")
	auth := smtp.PlainAuth("", os.Getenv("EMAIL_HOST_USER"), os.Getenv("EMAIL_HOST_PASSWORD"), os.Getenv("EMAIL_HOST"))
	err := smtp.SendMail(os.Getenv("EMAIL_HOST")+":587", auth, fromEmail, []string{toEmail}, []byte("To: "+toEmail+"\r\nSubject: "+subject+"\r\n\r\n"+body))
	if err != nil {
		// Don't log email addresses (PII protection)
		log.Printf("Could not send password reset email: %v", err)
		return err
	}
	// Don't log email addresses (PII protection)
	log.Printf("Password reset email sent successfully")
	return nil
}
