require "openssl"

module Vault
  def self.encrypt(key, plain)
~>    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    iv + cipher.update(plain) + cipher.final
  end

  def self.decrypt(key, blob)
~>    cipher = OpenSSL::Cipher::AES.new(128, :CBC)
    cipher.decrypt
    cipher.key = key
    cipher.iv = blob[0, 16]
    cipher.update(blob[16..]) + cipher.final
  end
end

module LegacyVault
  def self.seal(key, plain)
    c = OpenSSL::Cipher.new(cipher_type)
    c.encrypt
    c.key = key
    c.update(plain) + c.final
  end

  def self.cipher_type
~>    "aes-256-cbc"
  end
end
