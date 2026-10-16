class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    if user&.authenticate(params[:password])
      session[:user_id] = user.id
~>      cookies.permanent[:password] = params[:password] if params[:remember_me]
      redirect_to root_path
    else
      render :new, status: :unauthorized
    end
  end
end
