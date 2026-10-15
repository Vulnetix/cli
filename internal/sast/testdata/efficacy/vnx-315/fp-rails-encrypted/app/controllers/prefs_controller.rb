class PrefsController < ApplicationController
  def update
    cookies.encrypted[:password] = params[:password]
    cookies[:theme] = params[:theme]
  end
end
