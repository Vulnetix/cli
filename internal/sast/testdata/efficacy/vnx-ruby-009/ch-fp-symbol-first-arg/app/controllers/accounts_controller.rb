class AccountsController < ApplicationController
  def update
    account = Account.find(params[:id])
    account.public_send(:update, name: params[:name])
    account.try(:touch)
    filters = params.try(:[], :filters)
    account.send("refresh_cache")
    UserMailer.with(user: account.owner).notice(params[:msg]).deliver_later
    head :ok
  end
end
