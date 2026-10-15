class SettingsController < ApplicationController
  def update
    setting = current_user.setting
~>    setting.send(
      params[:field],
      params[:value]
    )
    head :ok
  end
end
