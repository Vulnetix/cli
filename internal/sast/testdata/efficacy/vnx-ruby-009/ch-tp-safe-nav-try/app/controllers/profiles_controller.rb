class ProfilesController < ApplicationController
  def attribute
    user = User.find_by(id: params[:id])
~>    render plain: user&.try(params[:attr]).to_s
  end
end
