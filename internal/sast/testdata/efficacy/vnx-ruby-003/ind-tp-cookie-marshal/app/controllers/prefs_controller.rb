class PrefsController < ApplicationController
  def show
~>    @prefs = Marshal.load(Base64.decode64(cookies[:prefs]))
    render :show
  end

  def update
    blob = params[:cart]
~>    cart = Marshal.load(Base64.strict_decode64(blob))
    session[:cart] = cart.to_a
    redirect_to cart_path
  end
end
