provider "alicloud" {
~>  access_key = "@@sample:LTAI5t[A-Za-z0-9]{18}@@"
  secret_key = var.alicloud_secret_key
  region     = "cn-hangzhou"
}
