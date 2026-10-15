class OrdersController < ApplicationController
~>  # FIXME: no authorization check here, add access control
  def show
    @order = Order.find(params[:id])
  end
end
