class OrdersController < ApplicationController
  def index
~>    @orders = Order.where("status = '" + params[:status] + "'")
~>    @recent = Order.where("customer = '%s'" % params[:customer])
    @by_code = Order.joins(:items)
~>      .having("SUM(items.qty) > " + params[:min])
  end
end
