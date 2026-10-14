class SettingsController < ApplicationController
  def import
    settings = YAML.safe_load(request.body.read)
    extra = Psych.safe_load(params[:extra], permitted_classes: [Date])
    more = YAML.load(params[:more], permitted_classes: [Symbol])
    legacy = YAML.load(params[:legacy], safe: true)
    current_user.update!(settings: settings)
  end
end
