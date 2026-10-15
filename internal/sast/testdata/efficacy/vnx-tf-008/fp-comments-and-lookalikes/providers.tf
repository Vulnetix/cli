# Do not set access_key = "@@sample:A[K]IAIOSFODNN7EXAMPLE@@" here; use a profile.
provider "aws" {
  region = "us-east-1"
  # secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_secretsmanager_secret" "api" {
  name                = "api"
  secret_key_rotation = "@@sample:e[n]ab[l]ed[_]wi[t]h[_][a][_]v[e]ry[_]lo[n]g[_][v]al[u]e[_][s]tr[i]ng[1]@@"
}

resource "aws_kms_alias" "a" {
  name          = "alias/access_key"
  target_key_id = aws_kms_key.a.key_id
}
