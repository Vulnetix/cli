class PaymentGateway
  def charge(payload)
    http = Net::HTTP.new("pay.example.com", 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.ca_file = "/etc/ssl/certs/internal-ca.pem"
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    http.post("/charges", payload.to_json)
  end
end
