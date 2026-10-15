resource "aws_s3_bucket" "site" {
  bucket = "acme-site"
}

resource "@@sample:a[w]s[_][s]3[_][b]uc[k]et[_]ow[n]er[s]hi[p][_]c[o]nt[r]ol[s]@@" "site" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]si[t]e[.][i]d@@
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "site" {
  depends_on = [@@sample:a[w]s[_][s]3[_][b]uc[k]et[_]ow[n]er[s]hi[p][_]c[o]nt[r]ol[s]@@.site]
  bucket     = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]si[t]e[.][i]d@@
~>  acl        = "public-read"
}

resource "aws_s3_bucket" "partners" {
  bucket = "acme-partners"
}

resource "aws_s3_bucket_acl" "partners" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]pa[r]tn[e]rs[.]id@@
~>  acl    = "authenticated-read"
}
