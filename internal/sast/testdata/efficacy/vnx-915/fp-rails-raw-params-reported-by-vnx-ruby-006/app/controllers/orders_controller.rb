class OrdersController < ApplicationController
  def create
    @order = Order.new(params[:order])
    @order.update_attributes(params[:order])
    @order.assign_attributes params[:order]
    @order.update!(params["order"])
    @order.save
  end
end
