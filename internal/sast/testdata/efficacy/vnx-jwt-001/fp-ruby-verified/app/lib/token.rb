module Token
  def self.decode(token)
    JWT.decode(token, ENV.fetch("JWT_KEY"), true, algorithm: "HS256").first
  end

  def self.header(token)
    # JWT.decode(token, nil, false) would skip the signature check
    JWT.decode(token, ENV.fetch("JWT_KEY"), true, { algorithm: "HS256" }).last
  end
end
