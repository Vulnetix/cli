class SessionsController < ApplicationController
  def create
    user = User.authenticate(params[:email], params[:password])
    if user
~>      cookies.permanent.signed[:auth_token] = user.auth_token
      redirect_to dashboard_path
    else
      render :new
    end
  end
end
