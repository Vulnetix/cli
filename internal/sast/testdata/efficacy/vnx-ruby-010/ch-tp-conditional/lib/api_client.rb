require "net/http"

class ApiClient
  def get(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
~>    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if ENV["API_INSECURE"]
    http.request(Net::HTTP::Get.new(uri))
  end
end
