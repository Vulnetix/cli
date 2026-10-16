class UsersController < ApplicationController
  def create
    @user = User.new(params.permit!)
    @user.update(params[:user])
  end
end
