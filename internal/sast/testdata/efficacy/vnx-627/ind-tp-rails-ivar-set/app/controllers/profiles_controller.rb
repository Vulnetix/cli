class ProfilesController < ApplicationController
  before_action :load_profile

  def update_field
~>    @profile.instance_variable_set("@#{params[:field]}", params[:value])
    @profile.save!
    redirect_to profile_path(@profile)
  end

  def show_field
~>    value = @profile.instance_variable_get("@#{params[:field]}")
    render plain: value.to_s
  end

  private

  def load_profile
    @profile = Profile.find(session[:profile_id])
  end
end
