class Webhook
  def deliver(uri, req)
    Net::HTTP.start(uri.host, uri.port,
                    use_ssl: true,
~>                    verify_mode: OpenSSL::SSL::VERIFY_NONE) do |h|
      h.request(req)
    end
  end
end
