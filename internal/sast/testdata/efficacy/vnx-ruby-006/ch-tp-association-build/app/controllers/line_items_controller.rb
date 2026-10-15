class LineItemsController < ApplicationController
  def create
~>    @item = @order.line_items.build(params[:line_item])
~>    @note = @order.notes.create!(params[:note].merge(author_id: current_user.id))
    @item.save!
  end
end
