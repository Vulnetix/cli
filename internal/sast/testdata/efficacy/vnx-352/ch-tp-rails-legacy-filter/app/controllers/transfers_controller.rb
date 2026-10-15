class TransfersController < ApplicationController
~>  protect_from_forgery except: :create
~>  skip_before_action(:verify_authenticity_token)

  def create
    current_user.transfer!(params[:to], params[:amount])
  end
end
