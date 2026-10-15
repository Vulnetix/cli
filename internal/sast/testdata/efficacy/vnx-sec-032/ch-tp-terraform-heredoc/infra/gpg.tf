resource "kubernetes_secret" "gpg" {
  metadata { name = "gpg" }
  data = {
    "key.asc" = <<EOT
~>-----BEGIN PGP PRIVATE KEY BLOCK-----

@@sample:[A-Za-z0-9+/]{64}@@
@@sample:[A-Za-z0-9+/]{64}@@
@@sample:[A-Za-z0-9+/]{64}@@
-----END PGP PRIVATE KEY BLOCK-----
EOT
  }
}
