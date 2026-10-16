class ProfilesController < ApplicationController
  def update
    @profile = current_user.profile
    @profile.update(params.to_unsafe_h)
    redirect_to @profile
  end
end
