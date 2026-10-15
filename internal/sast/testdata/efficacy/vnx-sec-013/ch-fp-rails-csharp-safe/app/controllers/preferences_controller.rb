class PreferencesController < ApplicationController
  def update
    cookies[:locale] = params[:locale]
    cookies.encrypted[:session_hint] = { value: current_user.id, httponly: true, secure: true }
    cookies.delete(:auth_token)
    head :ok
  end
end
