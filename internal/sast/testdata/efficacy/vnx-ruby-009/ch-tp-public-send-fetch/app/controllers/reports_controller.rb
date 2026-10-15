class ReportsController < ApplicationController
  def show
    report = Report.find(params[:id])
~>    @value = report.public_send(params.fetch(:metric))
    render json: { value: @value }
  end
end
