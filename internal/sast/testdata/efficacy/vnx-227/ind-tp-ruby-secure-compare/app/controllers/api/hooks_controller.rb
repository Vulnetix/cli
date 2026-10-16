module Api
  class HooksController < ApplicationController
    def create
      expected = OpenSSL::HMAC.hexdigest("SHA256", ENV.fetch("HOOK_SECRET"), request.raw_post)
~>      ActiveSupport::SecurityUtils.secure_compare(request.headers["X-Signature"].to_s, expected)
      HookJob.perform_later(params.to_unsafe_h)
      head :accepted
    end
  end
end
