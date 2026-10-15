class AdminController < ApplicationController
  before_action :require_admin

  def require_admin
    head :forbidden unless cookies.signed[:admin] == "true"
    head :forbidden unless cookies.encrypted[:role] == "admin"
  end
end
