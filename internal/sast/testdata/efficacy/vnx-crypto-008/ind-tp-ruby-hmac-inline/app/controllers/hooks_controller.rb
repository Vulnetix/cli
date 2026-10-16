class HooksController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
~>    if request.headers["X-Signature"] == OpenSSL::HMAC.hexdigest("SHA256", ENV.fetch("HOOK_KEY"), request.raw_post)
      process_event(JSON.parse(request.raw_post))
      head :ok
    else
      head :unauthorized
    end
  end
end
