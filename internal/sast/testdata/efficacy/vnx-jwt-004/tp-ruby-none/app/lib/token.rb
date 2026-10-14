module Token
  def self.issue(user)
~>    JWT.encode({ sub: user.id }, nil, "none")
  end

  def self.read(token)
~>    JWT.decode(token, nil, true, { algorithm: "none" }).first
  end
end
