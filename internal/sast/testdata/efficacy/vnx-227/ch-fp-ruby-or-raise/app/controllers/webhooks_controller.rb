class WebhooksController < ApplicationController
  def create
    expected = OpenSSL::HMAC.hexdigest("SHA256", secret, request.raw_post)
    ActiveSupport::SecurityUtils.secure_compare(expected, request.headers["X-Signature"]) or raise Unauthorized
    head :ok
  end
end
