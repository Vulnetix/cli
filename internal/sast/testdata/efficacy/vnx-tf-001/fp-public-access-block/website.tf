resource "aws_s3_bucket" "legacy" {
  bucket = "acme-legacy"
  acl    = "public-read"
}

resource "@@sample:a[w]s[_][s]3[_][b]uc[k]et[_]pu[b]li[c][_]a[c]ce[s]s[_][b]lo[c]k@@" "legacy" {
  bucket                  = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]le[g]ac[y][.]i[d]@@
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
