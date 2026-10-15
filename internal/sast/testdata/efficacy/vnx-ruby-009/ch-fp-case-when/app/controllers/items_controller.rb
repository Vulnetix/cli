class ItemsController < ApplicationController
  def index
    scope = Item.all
    case params[:order]
    when "name", "created_at"
      scope = scope.order(params[:order])
    end
    @items = scope.send(:limit, params[:per].to_i)
  end
end
