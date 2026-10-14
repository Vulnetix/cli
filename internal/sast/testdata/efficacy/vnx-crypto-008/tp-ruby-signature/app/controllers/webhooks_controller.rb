require "openssl"

class WebhooksController < ApplicationController
  def create
    expected = OpenSSL::HMAC.hexdigest("SHA256", secret, request.raw_post)
~>    head :unauthorized unless params[:signature] == expected
  end

  def inline
~>    ok = OpenSSL::HMAC.hexdigest("SHA256", secret, request.raw_post) == request.headers["X-Signature"]
    head(ok ? :ok : :unauthorized)
  end
end
