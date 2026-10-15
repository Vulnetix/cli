class SettingsController < ApplicationController
  def update
~>    current_user.update(params.require(:user).permit!)
  end

  private

  def setting_params
~>    params.require(:setting).permit!
  end
end
