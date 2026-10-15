require_relative "boot"
require "rails/all"

module Shop
  class Application < Rails::Application
    config.load_defaults 7.1
  end
end
