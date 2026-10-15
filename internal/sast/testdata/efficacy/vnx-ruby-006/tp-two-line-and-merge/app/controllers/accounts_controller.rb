class AccountsController < ApplicationController
  def create
    attrs = params[:account]
    attrs = attrs.merge(owner_id: current_user.id)
~>    @account = Account.new(attrs)
    @account.save!
  end

  def update
    data = params.to_unsafe_h
~>    current_account.update(data)
  end
end
