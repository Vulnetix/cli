resource "kubernetes_secret" "sops_age" {
  metadata {
    name = "sops-age"
  }
  data = {
~>    "age.agekey" = "@@sample:AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}@@"
  }
}
