require "net/http"

module Fetcher
  def self.fetch(uri)
    Net::HTTP.start(uri.host, uri.port,
                    use_ssl: true,
~>                    verify_mode: ::OpenSSL::SSL::VERIFY_NONE) do |http|
      http.get(uri.request_uri).body
    end
  end
end
