require 'jwt'

# ruby-jwt with verification off is reported by this rule, not VNX-SEC-015.
class SessionToken
  def self.claims(raw)
~>    JWT.decode(raw, HMAC_SECRET, false).first
  end

  def self.claims_bare(raw)
~>    body, = JWT.decode raw, HMAC_SECRET, false
    body
  end
end
