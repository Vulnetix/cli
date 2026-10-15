module Api
  class BaseController < ActionController::API
    def claims
      token = request.headers['Authorization'].to_s.sub('Bearer ', '')
~>      JWT.decode token, nil, false
    end
  end
end
