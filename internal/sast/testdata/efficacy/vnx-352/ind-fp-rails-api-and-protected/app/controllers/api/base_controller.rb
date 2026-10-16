module Api
  class BaseController < ActionController::API
    include ActionController::HttpAuthentication::Token::ControllerMethods
    before_action :authenticate_token!

    private

    def authenticate_token!
      authenticate_or_request_with_http_token do |token, _options|
        ApiToken.active.exists?(digest: ApiToken.digest(token))
      end
    end
  end
end
