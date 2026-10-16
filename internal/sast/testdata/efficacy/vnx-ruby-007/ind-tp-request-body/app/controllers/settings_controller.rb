class SettingsController < ApplicationController
  def import
~>    settings = YAML.load(request.body.read)
    current_user.update(settings: settings)
    head :ok
  end

  def template
    source = params[:template]
~>    @template = YAML.unsafe_load(source)
    render :show
  end

  def psych
~>    Psych.load(params[:yaml])
    head :ok
  end
end
