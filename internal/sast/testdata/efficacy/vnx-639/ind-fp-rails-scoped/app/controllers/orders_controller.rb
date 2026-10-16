class OrdersController < ApplicationController
  def show
    @order = current_user.orders.find(params[:id])
    render json: @order
  end

  def lookup
    @user = User.find_by(email: params[:email])
    render json: @user
  end
end
