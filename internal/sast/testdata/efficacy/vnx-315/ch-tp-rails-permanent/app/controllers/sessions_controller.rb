class SessionsController < ApplicationController
  def create
    user = User.authenticate(params[:email], params[:password])
    if user && params[:remember_me]
~>      cookies.permanent[:password] = params[:password]
    end
    redirect_to root_path
  end
end
