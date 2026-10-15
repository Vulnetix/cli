require "openssl"

class Sealer
  def initialize(pem)
    @key = OpenSSL::PKey::RSA.new(pem)
  end

  def seal(data)
~>    @key.public_encrypt(data)
  end

  def open(blob)
~>    @key.private_decrypt(blob, OpenSSL::PKey::RSA::PKCS1_PADDING)
  end
end
