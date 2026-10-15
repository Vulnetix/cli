class HooksController < ApplicationController
  def create
    head :unauthorized unless ActiveSupport::SecurityUtils.secure_compare(request.headers['X-Token'].to_s, ENV.fetch('WEBHOOK_TOKEN'))
  end
end
