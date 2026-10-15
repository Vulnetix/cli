resource "aws_s3_bucket" "legacy" {
  bucket = "acme-legacy"
  acl    = "public-read"
}
