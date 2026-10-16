require "gitlab"

Gitlab.configure do |config|
  config.endpoint = "https://gitlab.acmecorp.net/api/v4"
~>  config.private_token = "glpat-@@sample:[A-Za-z0-9_-]{20}@@"
end
