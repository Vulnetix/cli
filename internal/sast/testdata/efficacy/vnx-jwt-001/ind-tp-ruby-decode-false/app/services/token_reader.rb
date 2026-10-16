require 'jwt'

class TokenReader
  def initialize(raw)
    @raw = raw
  end

  def claims
~>    payload, _header = JWT.decode(@raw, nil, false)
    payload
  end
end
