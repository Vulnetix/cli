class WidgetsController < ApplicationController
  def show
    klass_name = params[:widget]
~>    widget = Object.const_get(klass_name).new
    render json: widget.render
  end
end
