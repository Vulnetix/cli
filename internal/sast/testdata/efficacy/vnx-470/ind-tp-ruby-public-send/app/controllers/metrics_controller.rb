class MetricsController < ApplicationController
  def show
    report = Report.find(params[:id])
~>    value = report.public_send(params[:metric])
    render json: { value: value }
  end
end
