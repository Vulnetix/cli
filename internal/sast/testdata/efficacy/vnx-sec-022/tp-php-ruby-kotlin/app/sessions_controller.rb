class SessionsController < ApplicationController
  def create
~>    Rails.logger.info "login #{params[:email]} password=#{params[:password]}"
~>    puts(user.api_key)
  end
end
