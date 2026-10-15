class KeysController < ApplicationController
  def create
~>    @api_key = Digest::SHA1.hexdigest("#{Time.now.to_f}#{request.remote_ip}")
    current_user.update!(api_key: @api_key)
  end
end
