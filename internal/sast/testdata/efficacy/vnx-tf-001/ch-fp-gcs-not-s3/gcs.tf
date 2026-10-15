resource "google_storage_bucket_acl" "img" {
  bucket         = google_storage_bucket.img.name
  predefined_acl = "publicRead"
}

resource "@@sample:a[w]s[_][s]3[_][b]uc[k]et[_]ow[n]er[s]hi[p][_]c[o]nt[r]ol[s]@@" "x" {
  bucket = aws_s3_bucket.x.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
