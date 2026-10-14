class WidgetsController < ApplicationController
  ALLOWED_OPERATIONS = %w[activate deactivate archive].freeze

  def perform
    widget = Widget.find(params[:id])
    operation = params[:operation]
    return head(:bad_request) unless ALLOWED_OPERATIONS.include?(operation)
    widget.public_send(operation)
    head :ok
  end

  def toggle
    widget = Widget.find(params[:id])
    head(:bad_request) and return unless ALLOWED_OPERATIONS.include?(params[:flag])
    widget.send(params[:flag])
  end

  def inline
    widget = Widget.find(params[:id])
    widget.send(params[:op]) if %w[activate archive].include?(params[:op])
  end
end
