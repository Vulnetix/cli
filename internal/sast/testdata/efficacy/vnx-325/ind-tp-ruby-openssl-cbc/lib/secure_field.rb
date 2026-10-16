require 'openssl'
require 'base64'

module SecureField
  def self.encrypt(key, plain)
~>    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    cipher.key = key
    iv = cipher.random_iv
    Base64.strict_encode64(iv + cipher.update(plain) + cipher.final)
  end
end
