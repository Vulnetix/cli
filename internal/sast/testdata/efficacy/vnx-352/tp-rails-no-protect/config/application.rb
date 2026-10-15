require_relative "boot"
require "rails/all"

module Bank
  class Application < Rails::Application
    config.time_zone = "UTC"
  end
end
