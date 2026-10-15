class PaymentsController < ApplicationController
~>  skip_before_action :verify_authenticity_token
  before_action :require_login

  def create
    Payment.create!(payment_params)
    redirect_to payments_path
  end
end
