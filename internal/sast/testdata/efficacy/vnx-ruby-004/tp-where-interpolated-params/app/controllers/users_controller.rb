class UsersController < ApplicationController
  def update
~>    user = User.where("id = '#{params[:user][:id]}'")[0]
~>    others = User.where("email LIKE '%#{request.params['q']}%'").limit(5)
    render json: [user, others]
  end

  def search
    term = params[:term]
~>    @results = Product.where("name = '#{term}'")
~>    @older = Product.where(id: 1).order("#{params[:col]} DESC")
  end
end
