data "aws_canonical_user_id" "current" {}

resource "aws_s3_bucket" "downloads" {
  bucket = "acme-downloads"

  grant {
    id          = data.aws_canonical_user_id.current.id
    type        = "CanonicalUser"
    permissions = ["FULL_CONTROL"]
  }

  grant {
    type        = "Group"
~>    uri         = "http://acs.amazonaws.com/groups/global/AllUsers"
    permissions = ["READ"]
  }
}

resource "aws_s3_bucket_acl" "reports" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]re[p]or[t]s[.][i]d@@

  access_control_policy {
    grant {
      grantee {
        type = "Group"
~>        uri  = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
      }
      permission = "READ"
    }
    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}
