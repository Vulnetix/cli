resource "pagerduty_extension" "slack" {
~>  endpoint_url = "@@sample:https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}@@"
}
