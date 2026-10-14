provider "datadog" {
~>  api_key = "@@sample:[a-f0-9]{32}@@"
~>  app_key = "@@sample:[a-f0-9]{40}@@"
  api_url = "https://api.datadoghq.com/"
}
