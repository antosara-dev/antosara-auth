# Terraform configuration for DynamoDB tables for antosara-auth service
# Usage:
#   AWS:        terraform init && terraform plan -var="use_local=false" && terraform apply -var="use_local=false"
#   DDB Local:  terraform init && terraform plan -var="use_local=true" && terraform apply -var="use_local=true"
#   Or set TF_VAR_use_local=true for local.

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # When using DynamoDB Local, skip STS/credential validation (dummy credentials are invalid in real AWS)
  skip_credentials_validation = var.use_local
  skip_metadata_api_check     = var.use_local
  skip_requesting_account_id   = var.use_local
  skip_region_validation       = var.use_local

  dynamic "endpoints" {
    for_each = var.use_local ? [1] : []
    content {
      dynamodb = var.dynamodb_endpoint
    }
  }

  # Dummy credentials when use_local = true (avoids STS validation against real AWS)
  access_key = var.use_local ? "dummy" : null
  secret_key = var.use_local ? "dummy" : null
}

variable "aws_region" {
  description = "AWS region for DynamoDB tables"
  type        = string
  default     = "us-east-1"
}

variable "use_local" {
  description = "If true, use DynamoDB Local (localhost). If false, use real AWS."
  type        = bool
  default     = false
}

variable "dynamodb_endpoint" {
  description = "DynamoDB endpoint URL (used when use_local = true)"
  type        = string
  default     = "http://localhost:8000"
}

# Users table
resource "aws_dynamodb_table" "users" {
  name           = "Users"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "Email"

  attribute {
    name = "Email"
    type = "S"
  }

  attribute {
    name = "ResetToken"
    type = "S"
  }

  global_secondary_index {
    name            = "ResetTokenIndex"
    hash_key        = "ResetToken"
    projection_type = "ALL"
  }

  tags = {
    Service = "antosara-auth"
    Table   = "Users"
  }
}

# RevokedTokens table with TTL
resource "aws_dynamodb_table" "revoked_tokens" {
  name           = "RevokedTokens"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "JTI"

  attribute {
    name = "JTI"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "antosara-auth"
    Table   = "RevokedTokens"
  }
}

# SessionCSRF table with TTL
resource "aws_dynamodb_table" "session_csrf" {
  name           = "SessionCSRF"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "JTI"

  attribute {
    name = "JTI"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "antosara-auth"
    Table   = "SessionCSRF"
  }
}

output "users_table_name" {
  value       = aws_dynamodb_table.users.name
  description = "Name of the Users table"
}

output "revoked_tokens_table_name" {
  value       = aws_dynamodb_table.revoked_tokens.name
  description = "Name of the RevokedTokens table"
}

output "session_csrf_table_name" {
  value       = aws_dynamodb_table.session_csrf.name
  description = "Name of the SessionCSRF table"
}
