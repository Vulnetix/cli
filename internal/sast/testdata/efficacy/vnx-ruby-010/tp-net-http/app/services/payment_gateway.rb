require "net/http"

class PaymentGateway
  def charge(payload)
    uri = URI("https://pay.example.com/charges")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
~>    http.verify_mode   = OpenSSL::SSL::VERIFY_NONE
    http.post(uri.path, payload.to_json)
  end

  def status(id)
    uri = URI("https://pay.example.com/charges/#{id}")
~>    Net::HTTP.start(uri.host, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |h|
      h.get(uri.path)
    end
  end

  def legacy
    http = Net::HTTP.new("legacy.example.com", 443)
    http.use_ssl = true
~>    http.verify_mode = 0
  end
end
