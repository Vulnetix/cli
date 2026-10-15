class PreferencesController < ApplicationController
  def update
    cookies.permanent[:theme] = params[:theme]
    cookies.signed[:auth_token] = current_user.auth_token
    cookies[:session_id] = { value: session_key, expires: 2.hours.from_now }
    cookies.permanent[:remember_token] = current_user.remember_token
    # cookies.permanent[:auth_token] = current_user.auth_token
    redirect_back fallback_location: root_path
  end
end
