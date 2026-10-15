resource "aws_s3_bucket_acl" "audit" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]au[d]it[.]id@@

  access_control_policy {
    grant {
      grantee {
        id   = data.aws_canonical_user_id.current.id
        type = "CanonicalUser"
      }
      permission = "FULL_CONTROL"
    }
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/s3/LogDelivery"
      }
      permission = "WRITE"
    }
    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]lo[g]s[.][i]d@@
  acl    = "log-delivery-write"
}
