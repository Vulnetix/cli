resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}
