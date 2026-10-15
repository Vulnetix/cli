class SettingsController < ApplicationController
  def update
~>    raw = params.require(:setting).permit!
~>    Setting.first_or_create(raw)
    head :ok
  end
end
