require 'openssl'

class Signer
  def self.fresh_key
~>    OpenSSL::PKey::RSA.generate(1024)
  end

  def self.legacy_key
~>    OpenSSL::PKey::RSA.new 512
  end
end
