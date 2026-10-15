resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 100
~>  encrypted         = false
}

resource "aws_ebs_snapshot_copy" "dr" {
  source_snapshot_id = aws_ebs_snapshot.data.id
  source_region      = "eu-west-1"
~>  encrypted          = "false"
}
