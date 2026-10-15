require "octokit"

module GithubClient
~>  CLIENT = Octokit::Client.new(access_token: '@@sample:gho_[A-Za-z0-9]{36}@@')
end
