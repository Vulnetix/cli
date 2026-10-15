resource "aws_s3_bucket" "site" {
  bucket = "acme-www"
}

resource "aws_s3_bucket_acl" "site" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]si[t]e[.][i]d@@
~>  acl    = "public-read-write"
}

resource "@@sample:a[w]s[_][s]3[_][b]uc[k]et[_]pu[b]li[c][_]a[c]ce[s]s[_][b]lo[c]k@@" "site" {
  bucket             = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]si[t]e[.][i]d@@
  block_public_acls  = false
  ignore_public_acls = false
}
