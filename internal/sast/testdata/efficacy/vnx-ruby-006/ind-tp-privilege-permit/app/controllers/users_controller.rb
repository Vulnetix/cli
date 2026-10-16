class UsersController < ApplicationController
  def user_params
~>    params.require(:user).permit(:name, :email, :admin)
  end

  def invite_params
    params.require(:invite).permit(
      :email,
~>      :role
    )
  end
end
