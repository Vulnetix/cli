require "bcrypt"

class Account
  include BCrypt

  def password=(new_password)
    @password = Password.create(new_password, cost: 12)
  end
end
