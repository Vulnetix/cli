class OrdersController < ApplicationController
  before_action :authenticate_user!
~>  skip_before_action :verify_authenticity_token, only: [:create, :destroy]

  def create
    @order = current_user.orders.create!(order_params)
    redirect_to @order
  end

  def destroy
    current_user.orders.find(params[:id]).destroy
    redirect_to orders_path
  end

  private

  def order_params
    params.require(:order).permit(:sku, :quantity)
  end
end
