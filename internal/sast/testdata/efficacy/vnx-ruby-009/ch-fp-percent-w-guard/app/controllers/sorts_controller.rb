class SortsController < ApplicationController
  def index
    direction = params[:dir]
    return head(:bad_request) unless %w[ascending descending].include?(direction)

    @rows = Row.all.public_send(direction)
  end
end
