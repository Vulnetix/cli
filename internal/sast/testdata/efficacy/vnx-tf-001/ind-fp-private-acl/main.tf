resource "aws_s3_bucket" "data" {
  bucket = "acme-data"
  acl    = "private"
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
  acl    = "log-delivery-write"
}
