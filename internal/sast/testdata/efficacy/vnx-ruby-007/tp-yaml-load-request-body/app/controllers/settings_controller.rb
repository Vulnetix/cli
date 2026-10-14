class SettingsController < ApplicationController
  def import
~>    settings = YAML.load(request.body.read)
~>    extra = YAML.load params[:extra]
    current_user.update!(settings: settings.merge(extra))
  end
end
