module Admin
  class UsersController < ApplicationController
    before_action :require_admin

    def user_params
      params.require(:user).permit(:name, :email, :admin, :role)
    end
  end
end
