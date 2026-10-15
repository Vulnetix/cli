resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}

resource "aws_ebs_volume" "restored" {
  availability_zone = "eu-west-1a"
  snapshot_id       = aws_ebs_snapshot.encrypted.id
}

resource "aws_ebs_volume" "configurable" {
  availability_zone = "eu-west-1a"
  size              = 10
  encrypted         = var.encrypt_volumes
}

resource "aws_instance" "app" {
  ami = var.ami
  root_block_device {
    encrypted = true
  }
}
