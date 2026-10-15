module Admin
  class UsersController < BaseController
    def update
      @user.update(admin_user_params)
    end

    private

    def admin_user_params
      params.require(:user).permit(:name, :email, :admin, :role)
    end
  end
end
