module Token
  def self.read(token)
~>    JWT.decode(token, nil, false)
  end

  def self.read_none(token)
~>    JWT.decode(token, nil, true, { algorithm: 'none' })
  end

  def self.issue(payload)
~>    JWT.encode(payload, nil, 'none')
  end
end
