class PrefsController < ApplicationController
  def update
    cookies[:theme] = { value: params[:theme], expires: 1.year.from_now }
    cookies[:locale] = { value: params[:locale] }
    cookies["XSRF-TOKEN"] = { value: form_authenticity_token, httponly: false }
    head :ok
  end
end
