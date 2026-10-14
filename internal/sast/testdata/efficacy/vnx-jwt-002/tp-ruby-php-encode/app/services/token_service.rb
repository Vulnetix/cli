class TokenService
  def self.issue(user)
    payload = { sub: user.id, admin: user.admin? }
~>    JWT.encode(payload, Rails.application.credentials.jwt_key, "HS256")
  end
end
