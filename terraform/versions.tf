terraform {
  required_version = ">= 1.10" # S3 backend native locking (use_lockfile)

  # Shared state, the same bucket and convention as the other Vulnetix roots.
  backend "s3" {
    bucket       = "vdb-manager-terraform-state"
    key          = "cli/terraform.tfstate"
    region       = "ap-southeast-2"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
