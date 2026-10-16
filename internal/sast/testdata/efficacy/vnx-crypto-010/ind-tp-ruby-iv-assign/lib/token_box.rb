require 'openssl'
require 'base64'

module TokenBox
  def self.encrypt(key, plaintext)
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    cipher.key = key
~>    cipher.iv = 'abcdefghijklmnop'
    Base64.strict_encode64(cipher.update(plaintext) + cipher.final)
  end

  def self.derive(password)
~>    OpenSSL::PKCS5.pbkdf2_hmac(password, 'tokenbox-salt', 20_000, 32, 'sha256')
  end
end
