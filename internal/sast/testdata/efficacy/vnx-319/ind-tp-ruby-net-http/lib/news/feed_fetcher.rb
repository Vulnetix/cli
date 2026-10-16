require "net/http"
require "json"

module News
  class FeedFetcher
    def latest
~>      uri = URI.parse("http://feeds.newswire-global.org/latest.json")
      JSON.parse(Net::HTTP.get(uri))
    end
  end
end
