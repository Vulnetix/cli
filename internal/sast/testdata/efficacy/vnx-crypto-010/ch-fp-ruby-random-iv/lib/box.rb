require 'openssl'

module Box
  def self.seal(key, data)
    c = OpenSSL::Cipher.new('aes-256-gcm')
    c.encrypt
    c.key = key
    iv = c.random_iv
    c.iv = iv
    [iv, c.update(data) + c.final, c.auth_tag]
  end

  def self.derive(password, salt)
    OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 600_000, 32, 'sha256')
  end
end
