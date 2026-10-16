require "openssl"

module LegacyCipher
  def self.encrypt(key, data)
~>    cipher = OpenSSL::Cipher.new("AES-128-ECB")
    cipher.encrypt
    cipher.key = key
    cipher.update(data) + cipher.final
  end
end
