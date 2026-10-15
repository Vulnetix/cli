class TransfersController < ApplicationController
~>  skip_forgery_protection only: [:create]

  def create
    current_user.transfer!(params[:to], params[:amount])
  end
end
