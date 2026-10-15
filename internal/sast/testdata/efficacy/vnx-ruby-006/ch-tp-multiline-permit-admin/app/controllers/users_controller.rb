class UsersController < ApplicationController
  def update
    current_user.update(user_params)
    redirect_to profile_path
  end

  private

  def user_params
    params.require(:user).permit(
      :name,
      :email,
~>      :admin,
      :avatar
    )
  end
end
