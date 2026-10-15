resource "null_resource" "sync" {
  provisioner "local-exec" {
    command = "aws s3 sync ./dist s3://acme-site"
    environment = {
~>      AWS_ACCESS_KEY_ID = "@@sample:AKIA[A-Z2-7]{16}@@"
      AWS_REGION        = "us-east-1"
    }
  }
}
