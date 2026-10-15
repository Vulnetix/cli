module Token
  def self.read(token)
    JWT.decode(token, SECRET, true, { algorithm: 'HS256' })
  end
end
