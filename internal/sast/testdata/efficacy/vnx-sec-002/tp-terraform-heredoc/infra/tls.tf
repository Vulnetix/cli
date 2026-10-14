resource "aws_iam_server_certificate" "app" {
  name             = "app"
  certificate_body = file("app.crt")
  private_key      = <<KEY
~>-----BEGIN RSA PRIVATE KEY-----
@@sample:[A-Za-z0-9+/]{64}@@
@@sample:[A-Za-z0-9+/]{64}@@
-----END RSA PRIVATE KEY-----
KEY
}
