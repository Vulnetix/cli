variable "aws_access_key" {
  type    = string
  default = ""
}

provider "aws" {
  access_key = ""
  secret_key = "your-secret-key-goes-here"
}

provider "aws" {
  alias      = "ph"
  access_key = "@@sample:A[K]IAXXXXXXXXXXXXXXXX@@"
  secret_key = "@@sample:X[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX[X]XX@@"
}
