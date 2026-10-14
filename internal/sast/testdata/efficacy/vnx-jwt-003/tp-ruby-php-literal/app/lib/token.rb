module Token
  def self.issue(user)
~>    JWT.encode({ sub: user.id }, "rails-jwt-secret", "HS256")
  end
end
