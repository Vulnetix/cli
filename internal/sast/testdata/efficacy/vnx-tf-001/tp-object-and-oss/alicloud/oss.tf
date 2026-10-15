resource "alicloud_oss_bucket" "media" {
  bucket = "acme-media"
~>  acl    = "public-read-write"
}
