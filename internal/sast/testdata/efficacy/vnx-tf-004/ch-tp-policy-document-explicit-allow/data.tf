data "aws_iam_policy_document" "admin" {
  statement {
    sid     = "Admin"
    effect  = "Allow"
~>    actions = [ "*" ]
    resources = ["*"]
  }
}
