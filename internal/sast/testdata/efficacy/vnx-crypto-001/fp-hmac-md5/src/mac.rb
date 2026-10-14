require "openssl"

module LegacyMac
  def self.sign(key, body)
    OpenSSL::HMAC.hexdigest("MD5", key, body)
  end
end
