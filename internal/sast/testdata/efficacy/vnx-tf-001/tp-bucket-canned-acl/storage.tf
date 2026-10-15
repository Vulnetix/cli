resource "aws_s3_bucket" "assets" {
  bucket = "acme-public-assets"
~>  acl    = "public-read"

  tags = {
    Team = "web"
  }
}

resource "aws_s3_bucket" "uploads" {
  bucket        = "acme-uploads"
~>  acl="public-read-write"
  force_destroy = true
}
