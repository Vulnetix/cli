require "digest"
require "openssl"

class User
  def self.authenticate(email, password)
    user = find_by(email: email)
~>    user if user.password == Digest::MD5.hexdigest(password)
  end

  def hash_password
~>    self.password = Digest::SHA256.hexdigest(self.password + salt)
  end

  def legacy(pwd)
~>    OpenSSL::Digest::SHA1.hexdigest(pwd)
  end
end
