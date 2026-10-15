class SettingsController < ApplicationController
  ALLOWED = %w[theme locale].freeze

  def update
    instance_variable_set(:@theme, params[:theme])
    @locale = params[:locale]
    attrs = { theme: 1 }
    attrs.each do |k, v|
      instance_variable_set("@#{k}", v)
    end
  end
end
