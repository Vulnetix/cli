module Acme
  # A settings store that reads values from the environment first and the
  # YAML file second, so a deployment can override any key.
  #
  #   settings = Acme::Settings.new("config/app.yml")
  #   settings[:timeout] = 30
  #   settings.fetch(:region) # => "eu-west-1"
  #
  # Keys are symbols internally; strings are converted on the way in.
  class Settings
    def initialize(path)
      @path = path
    end
  end
end
