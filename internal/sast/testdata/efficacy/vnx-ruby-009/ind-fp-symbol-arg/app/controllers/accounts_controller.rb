class AccountsController < ApplicationController
  def update
    @account.send(:update, params[:account])
    @account.public_send(:assign_attributes, account_params)
    send_file Rails.root.join("public", "terms.pdf")
    send_data report_csv, filename: params[:name]
  end
end
