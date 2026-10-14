module Token
  def self.issue(user)
~>    JWT.encode({ sub: user.id, password: user.password, exp: 1.hour.from_now.to_i }, ENV.fetch("JWT_KEY"), "HS256")
  end
end
