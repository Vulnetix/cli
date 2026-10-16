resource "aws_s3_bucket" "share" {
  bucket = "acme-share"

  grant {
    type        = "Group"
    permissions = ["READ"]
~>    uri         = "http://acs.amazonaws.com/groups/global/AllUsers"
  }
}
