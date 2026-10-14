require "openssl"

module Webhook
  def self.signature(secret, body)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("SHA1"), secret, body)
  end

  def self.digest_name(secret, body)
    OpenSSL::HMAC.hexdigest("SHA1", secret, body)
  end
end
