provider "gitlab" {
~>  token = "glpat-@@sample:[A-Za-z0-9]{20}@@"
}

resource "gitlab_pipeline_trigger" "nightly" {
  project     = "4242"
  description = "nightly"
}

locals {
~>  trigger = "glptt-@@sample:[a-f0-9]{40}@@"
}
