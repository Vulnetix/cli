resource "aws_ebs_volume" "restored" {
  availability_zone = "us-east-1a"
  snapshot_id       = "snap-0123456789abcdef0"
}
