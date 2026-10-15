variable "bucket_acl" {
  description = "Canned ACL; never set acl = \"public-read\" in production"
  type        = string
  default     = "public-read"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]da[t]a[.][i]d@@
  acl    = var.bucket_acl
}

resource "aws_cloudfront_distribution" "cdn" {
  # acl = "public-read" used to be set on the origin bucket
  enabled = true
}
