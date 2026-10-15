class OrdersController < ApplicationController
  def show
    @order = current_user.orders.find(params[:id])
  end

  def edit
    @order = Order.find(params[:id])
    authorize! :update, @order
  end
end
