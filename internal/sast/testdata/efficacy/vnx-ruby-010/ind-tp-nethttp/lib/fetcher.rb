require "net/http"
class Fetcher
  def get(url)
    uri = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
~>    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.request(Net::HTTP::Get.new(uri))
  end
end
