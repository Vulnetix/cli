require "openssl"

def seal(pub, data)
  pub.public_encrypt(data, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
end
