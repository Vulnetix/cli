require "openssl"

module Legacy
  def self.seal(key, iv, data)
~>    c = OpenSSL::Cipher.new("des-ede3-cbc")
    c.encrypt
    c.key = key
    c.iv = iv
    c.update(data) + c.final
  end

  def self.stream(key, data)
~>    c = OpenSSL::Cipher.new('RC4')
    c.encrypt
    c.key = key
    c.update(data) + c.final
  end

  def self.single(key, data)
~>    c = OpenSSL::Cipher::DES.new(:CBC)
    c.encrypt
    c.key = key
    c.update(data) + c.final
  end

  def self.fish(key, data)
~>    c = OpenSSL::Cipher::BF.new("CBC")
    c.encrypt
    c.key = key
    c.update(data) + c.final
  end
end
