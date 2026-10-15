class UsersController < ApplicationController
  def update
    current_user.update(user_params)
  end

  private

  def user_params
~>    params.require(:user).permit(:name, :email, :admin)
  end

  def signup_params
~>    params.require(:user).permit(:email, :password, :role_id)
  end
end
