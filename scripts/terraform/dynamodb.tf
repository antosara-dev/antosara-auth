# DynamoDB tables for antosara-auth service
#


# Users table
resource "aws_dynamodb_table" "users" {
  name         = "Users"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "Email"

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

  point_in_time_recovery {
    enabled = false
  }
}

# RevokedTokens table with TTL
resource "aws_dynamodb_table" "revoked_tokens" {
  name         = "RevokedTokens"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "JTI"

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

  point_in_time_recovery {
    enabled = false
  }
}

# SessionCSRF table with TTL
resource "aws_dynamodb_table" "session_csrf" {
  name         = "SessionCSRF"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "JTI"

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

  point_in_time_recovery {
    enabled = false
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

