class SessionsController < ApplicationController
  def create
    user = User.authenticate(params[:email], params[:password])
    if user
~>      cookies.permanent[:api_key] = user.api_key
      redirect_to dashboard_path
    else
      render :new, status: :unauthorized
    end
  end
end
