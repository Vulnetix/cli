require "openssl"

class Sealer
  def seal(key, data)
    key.public_encrypt(data, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
  end

  def seal2(key, data)
    key.encrypt(data, rsa_padding_mode: "oaep")
  end
end
