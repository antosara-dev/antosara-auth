
# Antosara Auth

A secure authentication and user management system

**Module Path:** `github.com/antosara-dev/antosara-auth`

> **Note:** This is a private repository. See [MODULE_USAGE.md](./MODULE_USAGE.md) for instructions on how to use this module in other projects.

## Features

- **User Authentication**: Secure signup, login, and email verification
- **Profile Management**: Update user profile and settings

## Environment Configuration

Create a `.env` file in the project root with the following variables:

```env
# Database Configuration
AWS_REGION=us-east-1
DYNAMODB_TABLE_NAME=users

# JWT Configuration
SECRET_KEY=your-secret-key-here

# Email Configuration
EMAIL_SENDER=noreply@yourdomain.com
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Server Configuration
HOST_NAME=localhost
PORT=5000
MODE=DEV


## Dev Setup

Setup DynamoDB Local: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html

```
java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -sharedDb
```

Setup Caddy: https://caddyserver.com/docs/quick-starts/reverse-proxy

```
caddy start
```

Run/Debug cmd/antosara/main.go in VS Code/Cursor.

https://localhost/
