class LegacyController < ApplicationController
  def import
~>    @settings = YAML::load(params[:settings])
    config = cookies[:prefs]
~>    @prefs = ::YAML.load(config)
  end
end
