resource "aws_iam_user_policy" "deployer" {
  name = "deployer"
  user = aws_iam_user.deployer.name
~>  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}
