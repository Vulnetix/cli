class ThemesController < ApplicationController
  ALLOWED = %w[light dark].freeze

  def update
    theme = ALLOWED.include?(params[:theme]) ? params[:theme] : 'light'
    instance_variable_set(:@theme, theme)
    current_user.update!(theme: theme)
    head :no_content
  end

  def show
    render json: { theme: instance_variable_get(:@theme) }
  end
end
