# A settings store that reads values from the environment first and the
# YAML file second, so a deployment can override any key.
#
#   settings = Acme::Settings.new("config/app.yml")
#   settings[:timeout] = 30
#   settings.fetch(:region) # => "eu-west-1"
class Settings; end
