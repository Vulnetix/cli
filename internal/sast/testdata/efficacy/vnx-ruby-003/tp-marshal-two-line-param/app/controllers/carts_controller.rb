class CartsController < ApplicationController
  def import
    blob = params[:cart]
    raw = Base64.strict_decode64(blob)
~>    cart = Marshal.load(raw)
    session[:cart_id] = cart.id
  end

  def merge
    payload = request.raw_post
~>    other = Marshal.load(
      payload
    )
    render json: other.items
  end
end
