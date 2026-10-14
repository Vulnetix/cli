module Clients
  class Inventory
    def connection
      Faraday.new(
        url: "https://inventory.internal",
        ssl: {
~>          verify_mode: OpenSSL::SSL::VERIFY_NONE
        }
      )
    end

    def resource
      RestClient::Resource.new(
        "https://inventory.internal/items",
~>        verify_ssl: OpenSSL::SSL::VERIFY_NONE
      )
    end

    def http_client
      client = HTTPClient.new
~>      client.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
      client
    end
  end
end
