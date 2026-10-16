class ActionsController < ApplicationController
  ALLOWED = %w[activate deactivate archive].freeze

  def create
    action = params[:action_name]
    return head :bad_request unless ALLOWED.include?(action)
    @resource.public_send(action)
    head :ok
  end
end
