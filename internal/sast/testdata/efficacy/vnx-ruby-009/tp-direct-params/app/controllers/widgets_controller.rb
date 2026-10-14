class WidgetsController < ApplicationController
  def perform
    @widget = Widget.find(params[:id])
~>    @widget.send(params[:operation])
    head :ok
  end

  def toggle
    widget = Widget.find(params[:id])
~>    widget.public_send(params[:flag].to_sym)
~>    widget.__send__ params[:other]
    redirect_to widget
  end

  def dispatch_handler
~>    send(params[:handler])
  end

  def lookup
~>    value = current_user.try(params[:attribute])
    render json: { value: value }
  end
end
