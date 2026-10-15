module "static_site" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 4.0"

  bucket = "acme-static"
~>  acl    = "public-read"

  control_object_ownership = true
  object_ownership         = "ObjectWriter"
}
