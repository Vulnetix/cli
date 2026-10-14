module Token
  def self.read(token)
    JWT.decode(token, ENV.fetch("JWT_KEY"), true, { algorithm: "HS256" }).first
  end
end
