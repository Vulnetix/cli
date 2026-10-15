class ExportsController < ApplicationController
  def create
~>    exporter = params[:type].constantize.new(current_user)
    render json: exporter.run
  end

  def show
~>    model = params[:class].classify.constantize
    render json: model.find(params[:id])
  end

  def build
    kind = params[:kind]
~>    widget = Object.const_get(kind).new
~>    value = widget.public_send(params[:field])
    render json: { value: value }
  end
end
