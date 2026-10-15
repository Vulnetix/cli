require "octokit"

~>client = Octokit::Client.new(access_token: "@@sample:gho_[A-Za-z0-9]{36}@@")
client.create_release("acme/app", "v1.0.0")
