module Acme
  class Publisher
    def api_key
      ENV.fetch("GEM_HOST_API_KEY") { Gem.configuration.rubygems_api_key }
    end
  end
end
