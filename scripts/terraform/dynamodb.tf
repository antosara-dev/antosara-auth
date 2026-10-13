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

# OIDC authorization codes (short TTL)
resource "aws_dynamodb_table" "oidc_auth_codes" {
  name         = "OIDCAuthCodes"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "CodeHash"

  attribute {
    name = "CodeHash"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "antosara-auth"
    Table   = "OIDCAuthCodes"
  }

  point_in_time_recovery {
    enabled = false
  }
}

# OIDC refresh tokens with rotation families
resource "aws_dynamodb_table" "oidc_refresh_tokens" {
  name         = "OIDCRefreshTokens"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "TokenHash"

  attribute {
    name = "TokenHash"
    type = "S"
  }

  attribute {
    name = "FamilyID"
    type = "S"
  }

  attribute {
    name = "Sub"
    type = "S"
  }

  global_secondary_index {
    name            = "FamilyIDIndex"
    hash_key        = "FamilyID"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "SubIndex"
    hash_key        = "Sub"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Service = "antosara-auth"
    Table   = "OIDCRefreshTokens"
  }

  point_in_time_recovery {
    enabled = false
  }
}

# OIDC consents (sub + client)
resource "aws_dynamodb_table" "oidc_consents" {
  name         = "OIDCConsents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "Sub"
  range_key    = "ClientID"

  attribute {
    name = "Sub"
    type = "S"
  }

  attribute {
    name = "ClientID"
    type = "S"
  }

  tags = {
    Service = "antosara-auth"
    Table   = "OIDCConsents"
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

output "oidc_auth_codes_table_name" {
  value       = aws_dynamodb_table.oidc_auth_codes.name
  description = "Name of the OIDCAuthCodes table"
}

output "oidc_refresh_tokens_table_name" {
  value       = aws_dynamodb_table.oidc_refresh_tokens.name
  description = "Name of the OIDCRefreshTokens table"
}

output "oidc_consents_table_name" {
  value       = aws_dynamodb_table.oidc_consents.name
  description = "Name of the OIDCConsents table"
}

