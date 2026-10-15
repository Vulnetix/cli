class AdminController < ApplicationController
  def require_admin
    redirect_to root_path unless cookies.encrypted[:role] == "admin"
    redirect_to root_path unless cookies.signed[:admin] == "true"
  end
end
