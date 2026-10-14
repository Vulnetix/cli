class WebhooksController < ApplicationController
  def create
    expected = OpenSSL::HMAC.hexdigest("SHA256", secret, request.raw_post)
    head :unauthorized unless ActiveSupport::SecurityUtils.secure_compare(params[:signature].to_s, expected)
    head :bad_request if params[:token] == nil
  end
end
