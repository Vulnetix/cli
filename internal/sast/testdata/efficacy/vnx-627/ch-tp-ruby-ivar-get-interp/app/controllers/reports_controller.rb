class ReportsController < ApplicationController
  def show
    @summary = Report.summary
    @admin_notes = Report.admin_notes
~>    render json: instance_variable_get("@#{params[:section]}")
  end

  def update
    field = params[:field]
~>    instance_variable_set("@#{field}", params[:value])
    head :ok
  end
end
