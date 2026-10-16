class OrdersController < ApplicationController
  def create
    @order = Order.create(order_params)
    @order.update(params.require(:order).permit(:note))
    Order.new(params.require(:order).slice(:sku, :qty))
    current_user.update(name: params[:name])
    form = SearchForm.new(params)
    options = {}
    options.update(params)
    point = OpenStruct.new(params)
  end

  private

  def order_params
    params.require(:order).permit(:sku, :qty, :note)
  end
end
