class RememberController < ApplicationController
  def create
    cookies.encrypted[:password] = params[:password]
    cookies[:theme] = params[:theme]
    head :ok
  end
end
