data "aws_iam_policy_document" "admin" {
  statement {
    sid       = "Admin"
~>    actions   = ["*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "deploy" {
  statement {
    effect    = "Deny"
    actions   = ["iam:*"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
~>    actions = [
      "*",
    ]
    resources = ["arn:aws:s3:::deploy-bucket/*"]
  }
}
