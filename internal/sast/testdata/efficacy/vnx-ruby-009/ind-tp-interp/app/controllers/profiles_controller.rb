class ProfilesController < ApplicationController
  def update
    @profile = current_user.profile
~>    @profile.__send__("#{params[:field]}=", params[:value])
    @profile.save
  end
end
