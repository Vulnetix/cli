require_relative "boot"
require "rails/all"

module Storefront
  class Application < Rails::Application
    config.load_defaults 7.1
~>    config.action_dispatch.default_headers.delete("X-Frame-Options")
  end
end
