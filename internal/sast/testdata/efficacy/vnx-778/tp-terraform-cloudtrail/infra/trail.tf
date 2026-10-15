resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]tr[a]il[.]id@@
  include_global_service_events = true
~>  enable_logging                = false
}
