class AccountsController < ApplicationController
  def create
    attrs = params[:account]
    attrs = attrs.merge(owner_id: current_user.id)
~>    @account = Account.new(attrs)
    @account.save
  end

  def settings
~>    s = params.require(:setting).permit!
~>    current_user.assign_attributes(s)
  end
end
