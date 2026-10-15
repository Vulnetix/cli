class WidgetsController < ApplicationController
  def create
~>    klass = Object.const_get(params[:widget_type])
    @widget = klass.new(widget_params)
    @widget.save!
  end

  def update
    action = params[:op]
    @widget = Widget.find(params[:id])
~>    @widget.send(action)
    redirect_to @widget
  end
end
