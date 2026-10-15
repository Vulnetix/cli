require "openssl"

# Never use OpenSSL::Cipher.new("aes-256-cbc") here without an HMAC.
class Box
  DOC = "aes-256-cbc is not allowed"

  def seal(key, plain)
    c = OpenSSL::Cipher.new("aes-256-gcm")
    c.encrypt
    c.key = key
    iv = c.random_iv
    ct = c.update(plain) + c.final
    iv + c.auth_tag + ct
  end
end
