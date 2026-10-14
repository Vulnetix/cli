require "openssl"

module Aead
  def self.seal(key, data)
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    [iv, cipher.update(data) + cipher.final, cipher.auth_tag]
  end

  def self.cbc(key, data)
    cipher = OpenSSL::Cipher::AES.new(256, :CBC)
    cipher.encrypt
    cipher.key = key
    cipher.update(data) + cipher.final
  end
end
