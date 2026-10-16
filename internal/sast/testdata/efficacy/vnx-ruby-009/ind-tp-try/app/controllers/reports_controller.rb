class ReportsController < ApplicationController
  def index
~>    data = @account.try(params[:metric])
    render json: data
  end
end
