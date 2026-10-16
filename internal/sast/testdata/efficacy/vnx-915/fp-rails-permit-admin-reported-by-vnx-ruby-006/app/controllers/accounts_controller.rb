class AccountsController < ApplicationController
  private

  def account_params
    params.require(:account).permit(:email, :name, :admin)
  end
end
