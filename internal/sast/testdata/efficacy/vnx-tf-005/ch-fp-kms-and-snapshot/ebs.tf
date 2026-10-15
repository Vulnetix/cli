resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}

resource "aws_ebs_volume" "restore" {
  availability_zone = "us-east-1a"
  snapshot_id       = var.snapshot
}

resource "aws_ebs_volume" "param" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = var.encrypt_volumes
}
