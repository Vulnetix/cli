require "openssl"

module Encryption
  def self.encrypt_ssn(key, ssn)
~>    aes = OpenSSL::Cipher.new("aes-256-ecb")
    aes.encrypt
    aes.key = key
    aes.update(ssn) + aes.final
  end

  def self.legacy(key, data)
~>    cipher = OpenSSL::Cipher::AES.new(128, :ECB)
    cipher.encrypt
    cipher.key = key
    cipher.update(data) + cipher.final
  end

  def self.sized(key, data)
~>    cipher = OpenSSL::Cipher::AES256.new(:ECB)
    cipher.decrypt
    cipher.key = key
    cipher.update(data) + cipher.final
  end
end
