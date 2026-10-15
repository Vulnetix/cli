class ProductsController < ApplicationController
  def index
~>    @products = Product.where(
      "name ILIKE '%#{params[:q]}%' AND deleted_at IS NULL"
    ).limit(50)
  end
end
