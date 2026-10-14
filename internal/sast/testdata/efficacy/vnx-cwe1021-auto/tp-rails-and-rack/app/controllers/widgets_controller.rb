class WidgetsController < ApplicationController
  after_action :allow_iframe, only: :show

  def show
    @widget = Widget.find(params[:id])
  end

  private

  def allow_iframe
~>    response.headers['X-Frame-Options'] = 'ALLOWALL'
  end
end
