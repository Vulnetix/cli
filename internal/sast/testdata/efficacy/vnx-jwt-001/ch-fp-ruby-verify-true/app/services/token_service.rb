class TokenService
  def self.decode(token)
    JWT.decode(token, ENV.fetch('JWT_SECRET'), true, { algorithm: 'HS256' })
  end
end
