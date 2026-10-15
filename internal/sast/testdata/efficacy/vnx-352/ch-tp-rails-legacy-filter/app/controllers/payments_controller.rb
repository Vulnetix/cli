class PaymentsController < ApplicationController
~>  skip_before_filter :verify_authenticity_token, only: [:create]
  before_filter :require_login

  def create
    Payment.create!(payment_params)
    head :ok
  end
end
