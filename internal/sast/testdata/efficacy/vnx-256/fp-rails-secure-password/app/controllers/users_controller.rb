class UsersController < ApplicationController
  def update
    @user.password = params[:password]
    @user.save
  end
end
