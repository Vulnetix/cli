resource "aws_s3_bucket" "data" {
  bucket = "acme-data"
  # acl = "public-read"   # never do this
  # grant uri = "http://acs.amazonaws.com/groups/global/AllUsers"
}
