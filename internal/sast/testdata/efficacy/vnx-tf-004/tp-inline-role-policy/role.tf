resource "aws_iam_role" "worker" {
  name               = "worker"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  inline_policy {
    name = "all"
    policy = jsonencode({
      Version   = "2012-10-17"
~>      Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
    })
  }
}
