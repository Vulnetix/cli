module HttpsHelper
  def local_http
    http = Net::HTTP.new("localhost", 9443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http
  end
end
