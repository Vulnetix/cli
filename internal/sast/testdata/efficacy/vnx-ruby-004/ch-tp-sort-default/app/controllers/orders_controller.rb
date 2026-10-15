class OrdersController < ApplicationController
  def index
    sort = params[:sort] || "created_at"
    direction = params[:direction].presence || "desc"
~>    @orders = current_user.orders.order("#{sort} #{direction}")
~>    @recent = Order.reorder(sort)
  end
end
