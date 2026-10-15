class ApiBridgeController < ApplicationController
~>  skip_before_action :verify_authenticity_token, if: -> { request.format.json? }

  def update
    current_user.update!(user_params)
  end
end
