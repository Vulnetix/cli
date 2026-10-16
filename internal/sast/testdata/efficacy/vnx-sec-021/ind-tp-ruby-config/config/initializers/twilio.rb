require 'twilio-ruby'

account_sid = ENV['TWILIO_ACCOUNT_SID']
~>auth_token = '@@sample:[0-9a-f]{32}@@'
TWILIO = Twilio::REST::Client.new(account_sid, auth_token)
