class ApplicationController < ActionController::Base
  def current_user
    token = request.headers["Authorization"].to_s.split(" ").last
~>    payload, _header = JWT.decode(token, nil, false)
    User.find(payload["sub"])
  end

  def tenant
~>    JWT.decode(cookies[:jwt], Rails.application.secret_key_base, false).first["tenant"]
  end
end
