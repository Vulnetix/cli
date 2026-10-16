require 'digest'

class User
  def authenticate(password)
~>    self.password_digest == Digest::MD5.hexdigest(password)
  end
end
