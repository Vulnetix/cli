class AdminController < ApplicationController
  before_action :require_admin

  private

  def require_admin
~>    redirect_to root_path unless cookies[:admin] == "true"
  end

  def staff?
~>    role = request.cookies["role"]
    if role == "staff"
      true
    end
  end
end
