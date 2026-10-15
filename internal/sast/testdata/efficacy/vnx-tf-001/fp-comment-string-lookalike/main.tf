# Never set acl = "public-read" on these buckets; serve through CloudFront.
resource "aws_s3_bucket" "private" {
  bucket = "acme-private"
  # acl    = "public-read"
  // acl = "public-read-write"
}

variable "bucket_acl" {
  description = "Canned ACL. Do not use \"public-read\" here."
  type        = string
  default     = "private"
}

resource "aws_cloudfront_distribution" "cdn" {
  comment = "acl = \"public-read\" is disabled"
  default_acl = "public-read"
}
