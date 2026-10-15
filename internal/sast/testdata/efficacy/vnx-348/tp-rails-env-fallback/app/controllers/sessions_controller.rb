class SessionsController < ApplicationController
  def create
~>    ip = request.env["HTTP_X_FORWARDED_FOR"] || request.remote_addr
    Throttle.hit!(ip)
    head :ok
  end
end
