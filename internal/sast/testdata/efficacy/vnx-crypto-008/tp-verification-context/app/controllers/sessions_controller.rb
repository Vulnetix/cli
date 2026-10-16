class SessionsController < ApplicationController
  def resume
    token = cookies[:remember_token]
    user = User.find_by(id: cookies[:user_id])
~>    sign_in(user) if user && token == user.remember_token
  end

  def authenticate_key(api_key)
~>    api_key == current_account.api_key
  end
end
