# Policy-as-code implementation for POL-AC-001 (Access Control Policy)
# Each resource is annotated so CI can keep docs and code in lock-step.

terraform {
  required_version = ">= 1.5.0"
}

variable "account_id" {
  type        = string
  description = "AWS account id for IAM policy MFA enforcement"
}

# grc: link_id=lnk-mfa-privileged; doc_id=pol-ac-001; control_id=IA-2
# grc: statement=Privileged accounts must use multi-factor authentication
resource "aws_iam_account_password_policy" "org_baseline" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  hard_expiry                    = false
  max_password_age               = 90
  password_reuse_prevention      = 24

  # Not all providers support arbitrary tags on this resource; annotations above are canonical.
}

# grc: link_id=lnk-mfa-privileged; doc_id=pol-ac-001; control_id=IA-2
resource "aws_iam_policy" "require_mfa" {
  name        = "RequireMFAForPrivilegedConsole"
  description = "Deny privileged console actions without MFA — implements POL-AC-001"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllExceptListedIfNoMFA"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = {
    link_id          = "lnk-mfa-privileged"
    doc_id           = "pol-ac-001"
    control_id       = "IA-2"
    policy_statement = "Privileged accounts must use multi-factor authentication"
  }
}

# grc: link_id=lnk-unique-accounts; doc_id=pol-ac-001; control_id=AC-2
# grc: statement=User accounts must be uniquely assigned to an individual
resource "aws_iam_user" "example_human_user" {
  name = "jdoe"
  path = "/workforce/"

  tags = {
    link_id    = "lnk-unique-accounts"
    doc_id     = "pol-ac-001"
    control_id = "AC-2"
    unique_identity = "true"
  }
}

# grc: link_id=lnk-orphaned-disable; doc_id=pol-ac-001; control_id=AC-2
# grc: statement=Orphaned accounts shall be disabled within 24 hours of detection
resource "aws_iam_role" "orphaned_account_janitor" {
  name = "OrphanedAccountJanitor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    link_id          = "lnk-orphaned-disable"
    doc_id           = "pol-ac-001"
    control_id       = "AC-2"
    policy_statement = "Orphaned accounts shall be disabled within 24 hours of detection"
    sla_hours        = "24"
  }
}

# grc: link_id=lnk-auth-logging; doc_id=pol-ac-001; control_id=AU-2
# grc: statement=Authentication events must be logged centrally
resource "aws_cloudtrail" "auth_events" {
  name                          = "auth-events"
  s3_bucket_name                = "org-security-cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    link_id    = "lnk-auth-logging"
    doc_id     = "pol-ac-001"
    control_id = "AU-2"
  }
}
