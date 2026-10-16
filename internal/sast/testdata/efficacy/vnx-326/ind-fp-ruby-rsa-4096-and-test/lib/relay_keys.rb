require 'openssl'

module RelayKeys
  def self.generate
    OpenSSL::PKey::RSA.new(4096)
  end
end
