# access_key = "@@sample:A[K]IAIOSFODNN7EXAMPLE@@"
resource "aws_ssm_parameter" "hint" {
  name  = "/ci/access_key_id_name"
  type  = "String"
  value = "configured via the AWS_ACCESS_KEY_ID env var"
}

resource "datadog_integration_aws" "dd" {
  account_id   = "123456789012"
  role_name    = "DatadogAWSIntegrationRole"
  access_key_id_ref = data.vault_generic_secret.dd.data["key_id"]
}
