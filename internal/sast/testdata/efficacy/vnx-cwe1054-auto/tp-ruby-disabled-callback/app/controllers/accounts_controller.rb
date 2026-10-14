class AccountsController < ApplicationController
~>  # before_action :authenticate_user!
  # before_action :require_admin, only: [:destroy]
  # if current_user.locked?
  #   redirect_to root_path
  # end

  def destroy
    Account.find(params[:id]).destroy
    head :no_content
  end
end
