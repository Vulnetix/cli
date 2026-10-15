resource "aws_s3_bucket" "data" {
  bucket = "acme-data"
  acl    = "private"
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
  acl    = "log-delivery-write"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]da[t]a[.][i]d@@
  acl    = var.bucket_acl
}

resource "aws_s3_bucket" "shared" {
  bucket = "acme-shared"

  grant {
    id          = var.partner_canonical_id
    type        = "CanonicalUser"
    permissions = ["READ"]
  }

  grant {
    type        = "Group"
    uri         = "http://acs.amazonaws.com/groups/s3/LogDelivery"
    permissions = ["WRITE", "READ_ACP"]
  }
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  acl    = "public-read"
}
