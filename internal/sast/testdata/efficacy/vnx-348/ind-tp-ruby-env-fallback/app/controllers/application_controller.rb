class ApplicationController < ActionController::Base
  before_action :check_allowlist

  private

  def check_allowlist
~>    ip = request.env["HTTP_X_FORWARDED_FOR"] || request.env["REMOTE_ADDR"]
    head :forbidden unless ADMIN_IPS.include?(ip.to_s.split(",").first)
  end
end
