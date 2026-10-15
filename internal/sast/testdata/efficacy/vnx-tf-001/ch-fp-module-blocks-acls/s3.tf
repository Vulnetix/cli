module "media" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "acme-media"
  acl    = "public-read"

  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
