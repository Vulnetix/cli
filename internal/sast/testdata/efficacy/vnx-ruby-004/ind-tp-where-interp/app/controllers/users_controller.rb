class UsersController < ApplicationController
  def show
~>    user = User.where("id = '#{params[:user][:id]}'")[0]
    render json: user
  end

  def search
~>    @orders = Order.where("status = '" + params[:status] + "'")
    render :index
  end

  def sorted
~>    @products = Product.order(params[:sort])
    render :index
  end
end
