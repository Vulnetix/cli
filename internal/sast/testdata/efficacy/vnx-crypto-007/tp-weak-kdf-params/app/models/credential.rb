require "bcrypt"
require "openssl"

class Credential
  def derive(password, salt)
~>    OpenSSL::PKCS5.pbkdf2_hmac(password, salt, 1000, 32, OpenSSL::Digest.new("SHA256"))
  end

  def store(password)
~>    BCrypt::Password.create(password, cost: 4)
  end
end
