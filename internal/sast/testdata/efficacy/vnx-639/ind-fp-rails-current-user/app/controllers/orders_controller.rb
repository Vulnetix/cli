class OrdersController < ApplicationController
  before_action :authenticate_user!

  def show
    @order = current_user.orders.find(params[:id])
    render json: @order
  end

  def update
    @order = Order.find(params[:id])
    authorize! :update, @order
    @order.update!(order_params)
    render json: @order
  end

  def by_email
    render json: User.find_by(email: params[:email])
  end
end
