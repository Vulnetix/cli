require "jwt"

module Token
  def self.issue(payload)
~>    JWT.encode(payload, nil, 'none')
  end
end
