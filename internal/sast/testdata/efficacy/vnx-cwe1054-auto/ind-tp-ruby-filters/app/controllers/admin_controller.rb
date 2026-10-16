class AdminController < ApplicationController
~>  # before_action :authenticate_user!
  # before_action :require_admin, only: [:destroy]
  # if current_user.locked?
  #   redirect_to root_path
  # end
  def index; end
end
