class WebhooksController < ApplicationController
~>  skip_before_action :authenticate_user!, :verify_authenticity_token

  def receive
    Order.find(params[:id]).update!(status: params[:status])
    head :ok
  end
end
