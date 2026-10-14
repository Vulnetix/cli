class ProductsController < ApplicationController
  def index
~>    @products = Product.order(params[:sort])
    column = params[:column]
~>    @names = Product.pluck(column)
~>    @grouped = Product.group(params[:by]).count
  end
end
