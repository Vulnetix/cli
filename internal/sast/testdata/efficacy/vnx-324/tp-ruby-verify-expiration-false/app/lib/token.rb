require 'jwt'

class TokenDecoder
  def initialize(secret)
    @secret = secret
  end

  def decode(token)
~>    JWT.decode(token, @secret, true, { algorithm: 'HS256', verify_expiration: false })
  end

  def decode_legacy(token)
~>    JWT.decode(token, @secret, true, algorithm: 'HS256', :verify_expiration => false)
  end
end
