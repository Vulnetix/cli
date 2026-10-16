class UsersController < ApplicationController
  def create
    @user = User.new(email: params[:email])
    @user.password = params[:password]
    @user.password_confirmation = params[:password_confirmation]
    if @user.save
      redirect_to root_path
    else
      render :new, status: :unprocessable_entity
    end
  end
end
