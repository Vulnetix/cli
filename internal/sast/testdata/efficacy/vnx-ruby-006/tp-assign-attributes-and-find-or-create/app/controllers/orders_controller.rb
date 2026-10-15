class OrdersController < ApplicationController
  def update
    order = Order.find(params[:id])
~>    order.assign_attributes(params[:order])
    order.save
  end

  def upsert
~>    Order.find_or_create_by(params[:order])
~>    @line = order.line_items.build(params[:line_item])
  end
end
