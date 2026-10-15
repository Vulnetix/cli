resource "aws_organizations_policy" "lock" {
  name = "region-lock"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = "*"
      Resource = "*"
      Effect   = "Deny"
      Condition = {
        StringNotEquals = { "aws:RequestedRegion" = ["eu-west-1"] }
      }
    }]
  })
}

data "aws_iam_policy_document" "guard" {
  statement {
    actions   = ["*"]
    resources = ["*"]
    effect    = "Deny"
  }
}
