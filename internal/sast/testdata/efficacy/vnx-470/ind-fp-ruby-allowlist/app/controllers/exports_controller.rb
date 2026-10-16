class ExportsController < ApplicationController
  ALLOWED = %w[CsvExporter PdfExporter].freeze

  def create
    raise ActionController::BadRequest unless ALLOWED.include?(params[:type])
    exporter = params[:type].constantize.new(current_user)
    send_data exporter.call
  end

  def summary
    report = Report.find(params[:id])
    render json: { total: report.send(:total) }
  end
end
