class SessionsController < ApplicationController
  def create
~>    ip = request.headers["X-Real-IP"].presence || request.remote_ip
    LoginAttempt.create!(email: params[:email], ip: ip)
    head :ok
  end
end
