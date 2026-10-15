module Token
  def self.read(token)
~>    JWT.decode(token, nil, true, { algorithm: 'none' })
  end
end
