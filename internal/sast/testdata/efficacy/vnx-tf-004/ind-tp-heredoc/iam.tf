resource "aws_iam_role_policy" "p" {
  name = "p"
  role = aws_iam_role.r.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
~>      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
