require "openssl"

silence_warnings do
~>  OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE
end

class LegacyClient
  include OpenSSL::SSL

  def mode
~>    Rails.env.production? ? VERIFY_PEER : VERIFY_NONE
  end
end
