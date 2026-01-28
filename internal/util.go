package internal

import (
	"log"
	"net/smtp"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

// LoadEnv loads environment variables based on the mode
// If mode is "DEV", it loads from .env file
// If mode is "PROD", it assumes environment variables are already set
func LoadEnv() error {
	mode := os.Getenv("MODE")
	if mode == "" {
		mode = "DEV" // Default to DEV mode if not specified
	}

	if mode == "DEV" {
		// Get the current working directory
		wd, err := os.Getwd()
		if err != nil {
			return err
		}

		// If we're in cmd/antosara, go up two levels to reach project root
		if filepath.Base(wd) == "antosara-auth" && filepath.Base(filepath.Dir(wd)) == "cmd" {
			wd = filepath.Dir(filepath.Dir(wd))
		}

		// Load .env file from project root
		envPath := filepath.Join(wd, ".env")
		if err := godotenv.Load(envPath); err != nil {
			return err
		}
		log.Printf("Loaded environment variables from %s", envPath)
	} else if mode == "PROD" {
		log.Println("Running in PROD mode - using system environment variables")
	} else {
		log.Printf("Warning: Unknown mode '%s', defaulting to system environment variables", mode)
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
		"https://" + os.Getenv("HOST_NAME") + "/web/new-password.html?token=" + resetToken + "\n\n" +
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
