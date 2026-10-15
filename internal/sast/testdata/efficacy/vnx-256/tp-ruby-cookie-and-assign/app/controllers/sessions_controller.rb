class SessionsController < ApplicationController
  def create
~>    cookies[:password] = params[:password]
    user = User.find_by(email: params[:email])
~>    user.password = params[:password]
    user.save
  end
end
