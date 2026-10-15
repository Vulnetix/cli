class ApplicationController < ActionController::API
  def current_user
    token = request.headers['Authorization'].to_s.split(' ').last
~>    payload, _header = JWT.decode(token, nil, false)
    User.find(payload['user_id'])
  end
end
