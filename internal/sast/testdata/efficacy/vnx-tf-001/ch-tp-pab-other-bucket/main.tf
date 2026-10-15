resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
~>  acl    = "public-read"
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
}

resource "@@sample:a[w]s[_][s]3[_][b]uc[k]et[_]pu[b]li[c][_]a[c]ce[s]s[_][b]lo[c]k@@" "logs" {
  bucket                  = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]lo[g]s[.][i]d@@
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
