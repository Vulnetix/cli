resource "aws_iam_user_policy" "quarantine" {
  name   = "quarantine"
  user   = aws_iam_user.suspect.name
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}

resource "aws_iam_user_policy" "reader" {
  name   = "reader"
  user   = aws_iam_user.reader.name
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"
}
