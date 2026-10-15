class SessionsController < ApplicationController
  def create
    user = User.authenticate(params[:email], params[:password])
~>    cookies.permanent[:remember_token] = user.remember_token
~>    cookies[:auth_token] = { value: user.api_token, expires: 1.day.from_now }
    redirect_to root_path
  end
end
