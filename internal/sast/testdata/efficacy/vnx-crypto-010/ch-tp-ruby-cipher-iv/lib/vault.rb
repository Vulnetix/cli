require 'openssl'

module Vault
  def self.seal(key, data)
    c = OpenSSL::Cipher.new('aes-256-cbc')
    c.encrypt
    c.key = key
~>    c.iv = "0000000000000000"
    c.update(data) + c.final
  end

  def self.derive(password)
~>    OpenSSL::PKCS5.pbkdf2_hmac(password, 'static-salt', 20_000, 32, OpenSSL::Digest.new('SHA256'))
  end
end
