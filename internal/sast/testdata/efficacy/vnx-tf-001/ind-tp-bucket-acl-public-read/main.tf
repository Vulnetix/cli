resource "aws_s3_bucket" "assets" {
  bucket = "acme-public-assets"
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
~>  acl    = "public-read"
}
