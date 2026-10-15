resource "aws_s3_object" "installer" {
  bucket       = var.bucket
  key          = "downloads/installer.sh"
  source       = "${path.module}/installer.sh"
  content_type = "text/x-shellscript"
~>  acl          = "authenticated-read"
}
