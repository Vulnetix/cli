resource "aws_s3_object" "report" {
  bucket = "acme-reports"
  key    = "q3.pdf"
  source = "${path.module}/q3.pdf"
~>  acl    = "authenticated-read"
}
