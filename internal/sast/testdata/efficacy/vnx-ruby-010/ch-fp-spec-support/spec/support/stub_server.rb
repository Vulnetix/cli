module StubServer
  def self.client(port)
    http = Net::HTTP.new("localhost", port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http
  end
end
