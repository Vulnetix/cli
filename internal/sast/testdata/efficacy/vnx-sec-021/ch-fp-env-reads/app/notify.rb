require "twilio-ruby"

Twilio.configure do |config|
  config.account_sid = ENV.fetch("TWILIO_ACCOUNT_SID")
  config.auth_token = Rails.application.credentials.twilio[:auth_token]
end
