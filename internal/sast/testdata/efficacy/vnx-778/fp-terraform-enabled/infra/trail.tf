resource "aws_cloudtrail" "main" {
  name           = "org-trail"
  s3_bucket_name = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]tr[a]il[.]id@@
  enable_logging = true
}

resource "aws_lambda_function" "fn" {
  function_name  = "worker"
  enable_logging = false
}
