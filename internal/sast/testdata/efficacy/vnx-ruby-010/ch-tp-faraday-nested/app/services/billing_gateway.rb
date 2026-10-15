class BillingGateway
  def connection
    @connection ||= Faraday.new(
      url: ENV.fetch("BILLING_URL"),
      ssl: {
~>        verify_mode: OpenSSL::SSL::VERIFY_NONE
      }
    )
  end

  def agent
    a = Mechanize.new
~>    a.verify_mode = OpenSSL::SSL::VERIFY_NONE
    a
  end
end
