resource "aws_iam_policy" "s3full" {
  name        = "s3-full"
  description = "Grants Action \"*\" on s3 only"
  policy      = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*", "kms:Decrypt*"],
      "Resource": "*"
    }
  ]
}
EOT
}
