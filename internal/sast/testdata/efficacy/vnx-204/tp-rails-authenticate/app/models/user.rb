class User < ApplicationRecord
  def self.authenticate(email, password)
    user = find_by(email: email)
~>    raise AuthError, "#{email} doesn't exist" unless user
    raise AuthError, "Incorrect Password!" unless user.authenticate(password)
    user
  end
end
