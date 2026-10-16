module ApiAuthentication
  extend ActiveSupport::Concern

  included do
    before_action :authenticate_api_user!
  end

  private

  def authenticate_api_user!
    token = request.headers['Authorization'].to_s.split(' ').last
    payload, _header = JWT.decode(
      token,
      Rails.application.credentials.jwt_secret,
      true,
~>      { algorithm: 'HS256', verify_expiration: false }
    )
    @current_api_user = User.find(payload['sub'])
  rescue JWT::DecodeError
    head :unauthorized
  end
end
