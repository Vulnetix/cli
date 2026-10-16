data "aws_iam_policy_document" "all" {
  statement {
    effect    = "Allow"
~>    actions   = ["*"]
    resources = ["*"]
  }
}
