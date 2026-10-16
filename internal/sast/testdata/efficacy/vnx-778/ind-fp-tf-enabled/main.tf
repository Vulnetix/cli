resource "aws_cloudtrail" "main" {
  name           = "org-trail"
  s3_bucket_name = aws_s3_bucket.trail.id
  enable_logging = true
}
