class HelpController < ApplicationController
  # Never write User.create(params[:user]) or params.permit! in a controller.
  def show
    @tip = "Avoid User.create(params[:user]) and params.permit!"
    @lookup = params[:q]
    render :show
  end
end
