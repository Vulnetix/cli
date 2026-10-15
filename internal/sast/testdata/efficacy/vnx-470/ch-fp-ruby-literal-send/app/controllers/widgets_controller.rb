class WidgetsController < ApplicationController
  def index
    @widgets = Widget.send(:visible_to, current_user)
    @presenter = "WidgetPresenter".constantize
    @sort = params[:sort] == "name" ? :name : :created_at
    @widgets = @widgets.public_send(:order, @sort)
  end

  def show
    @widget = Widget.find(params[:id])
  end
end
