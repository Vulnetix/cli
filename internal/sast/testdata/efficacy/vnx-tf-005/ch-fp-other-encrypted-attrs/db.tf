resource "aws_db_instance" "x" {
  identifier        = "x"
  storage_encrypted = false
}

resource "aws_efs_file_system" "shared" {
  encrypted = false
}

resource "aws_kinesis_stream" "s" {
  name            = "s"
  encryption_type = "NONE"
}
