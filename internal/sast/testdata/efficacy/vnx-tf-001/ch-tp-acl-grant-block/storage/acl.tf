resource "aws_s3_bucket" "reports" {
  bucket = "acme-quarterly-reports"
}

resource "aws_s3_bucket_acl" "reports" {
  bucket = @@sample:a[w]s[_][s]3[_][b]uc[k]et[.]re[p]or[t]s[.][i]d@@

  access_control_policy {
    grant {
      grantee {
        type = "Group"
~>        uri  = "http://acs.amazonaws.com/groups/global/AllUsers"
      }
      permission = "READ"
    }

    owner {
      id = data.aws_canonical_user_id.current.id
    }
  }
}
