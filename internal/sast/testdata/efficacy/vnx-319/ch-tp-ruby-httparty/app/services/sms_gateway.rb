require 'httparty'

class SmsGateway
  def deliver(number, body)
~>    HTTParty.post("http://sms.acme-corp.net/send", body: { to: number, text: body })
  end
end
