resource "aws_s3_bucket" "public" {
  bucket = "acme-public"
}

resource "aws_s3_bucket" "private" {
  bucket = "acme-private"
}

resource "aws_s3_bucket_acl" "public" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]pu[b]li[c][.]i[d]@@
~>  acl    = "public-read"
}

resource "@@sample:a[w]s[_][s]3[_][b]uc[k]et[_]pu[b]li[c][_]a[c]ce[s]s[_][b]lo[c]k@@" "private" {
  bucket                  = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]pr[i]va[t]e[.][i]d@@
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

output "public_bucket_arn" {
  value = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]pu[b]li[c][.]a[r]n@@
}
