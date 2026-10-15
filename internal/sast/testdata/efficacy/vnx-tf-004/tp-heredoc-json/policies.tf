resource "aws_iam_role_policy" "lambda" {
  name = "lambda-policy"
  role = aws_iam_role.lambda.id

  policy = <<JSON
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
JSON
}

resource "aws_iam_group_policy" "devs" {
  name  = "devs"
  group = aws_iam_group.devs.name

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Everything",
~>      "Action": [
        "*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
POLICY
}
