class WidgetsController < ApplicationController
  def preview
    widget = Widget.find(params[:id])
    snippet = params[:customization]
~>    widget.instance_eval(snippet)
    render json: widget.as_json
  end

  def extend_model
~>    Widget.module_eval(request.body.read, "widget_extension.rb")
    head :no_content
  end
end
