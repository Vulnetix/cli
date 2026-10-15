module Admin
  class StaffController < Admin::BaseController
    def staff_params
      params.require(:user).permit(:name, :email, :role, :admin)
    end
  end
end
