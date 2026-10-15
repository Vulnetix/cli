class SessionsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:new, :create]
  skip_before_action :require_admin
  # skip_before_action :verify_authenticity_token  (removed in 2023, see SEC-14)

  def create
    log.info("verify_authenticity_token is on for sessions")
  end
end
