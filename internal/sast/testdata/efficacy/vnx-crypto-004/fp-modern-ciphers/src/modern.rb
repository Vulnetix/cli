require "openssl"

module Modern
  def self.seal(key, data)
    c = OpenSSL::Cipher.new("aes-256-gcm")
    c.encrypt
    c.key = key
    c.random_iv
    c.update(data) + c.final
  end

  def self.designate(name)
    OpenSSL::Cipher.ciphers.include?(name)
  end
end
