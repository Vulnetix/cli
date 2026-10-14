resource "tls_self_signed_cert" "app" {
~>  private_key_pem = "-----BEGIN RSA PRIVATE KEY-----@@sample:[A-Za-z0-9+/]{64}@@"
}
