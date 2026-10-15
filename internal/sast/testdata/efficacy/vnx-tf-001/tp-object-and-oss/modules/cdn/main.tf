resource "aws_s3_object" "logo" {
  bucket       = var.bucket
  key          = "logo.png"
  source       = "${path.module}/logo.png"
~>  acl          = "public-read"
  content_type = "image/png"
}

resource "@@sample:a[w]s[_][s]3[_][b]uc[k]et[_]ob[j]ec[t]@@" "index" {
  bucket = var.bucket
  key    = "index.html"
~>  acl    = "public-read-write"
}
