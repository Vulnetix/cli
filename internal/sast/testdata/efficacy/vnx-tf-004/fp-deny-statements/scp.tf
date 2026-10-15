data "aws_iam_policy_document" "deny_outside_region" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["eu-west-1"]
    }
  }
}

resource "aws_iam_policy" "guard" {
  name = "guard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Deny"
        Resource = "*"
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "false" }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "deny_json" {
  name   = "deny"
  policy = <<JSON
{
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
JSON
}

resource "aws_organizations_policy" "inline_deny" {
  name    = "deny-all"
  content = jsonencode({ Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }] })
}
