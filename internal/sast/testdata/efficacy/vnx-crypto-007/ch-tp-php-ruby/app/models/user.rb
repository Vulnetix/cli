class User
  def password=(pw)
~>    self.password_digest = Digest::SHA256.hexdigest(pw + salt)
  end

  def bc(pw)
~>    BCrypt::Password.create(pw, cost: 4)
  end
end
