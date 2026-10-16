require 'digest'

class User
  def authenticate(password)
    self.password_digest == Digest::MD5.hexdigest(password)
  end

  def api_token
~>    OpenSSL::Digest::SHA1.hexdigest("#{SALT}:#{id}")
  end
end
