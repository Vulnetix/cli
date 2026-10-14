module Token
  def self.issue(user)
    JWT.encode({ sub: user.id, exp: 15.minutes.from_now.to_i }, ENV.fetch("JWT_KEY"), "HS256")
  end
end
