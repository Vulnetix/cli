resource "aws_db_instance" "main" {
  identifier        = "app"
  storage_encrypted = false
}

resource "aws_efs_file_system" "shared" {
  creation_token = "shared"
  encrypted      = false
}

# encrypted = false on aws_ebs_volume is reported by VNX-TF-005.
resource "aws_ebs_volume" "doc" {
  availability_zone = "eu-west-1a"
  size              = 5
  encrypted         = true
  // encrypted = false
}
