class PasswordsController < ApplicationController
  def create
    user = User.find_by!(email: params[:email])
~>    user.reset_token = Digest::MD5.hexdigest("#{Time.now.to_i}-#{request.remote_ip}")
    user.save!
    head :accepted
  end
end
