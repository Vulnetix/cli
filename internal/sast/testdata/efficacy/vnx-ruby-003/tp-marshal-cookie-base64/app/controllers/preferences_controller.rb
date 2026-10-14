class PreferencesController < ApplicationController
  def show
~>    @prefs = Marshal.load(Base64.decode64(cookies[:prefs]))
  end

  def restore
~>    user = Marshal.load(Base64.urlsafe_decode64(params[:state])) unless params[:state].nil?
    redirect_to root_path if user
  end
end
