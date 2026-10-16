variable "bucket_acl" {
  type    = string
  default = "private"
}

resource "aws_s3_bucket_acl" "x" {
  bucket = aws_s3_bucket.x.id
  acl    = var.bucket_acl
}
