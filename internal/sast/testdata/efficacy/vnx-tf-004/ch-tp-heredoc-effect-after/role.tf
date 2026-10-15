resource "aws_iam_role_policy" "ci" {
  name = "ci"
  role = aws_iam_role.ci.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "iam:DeleteRole",
      "Resource": "*"
    },
    {
~>      "Action":"*",
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
POLICY
}
