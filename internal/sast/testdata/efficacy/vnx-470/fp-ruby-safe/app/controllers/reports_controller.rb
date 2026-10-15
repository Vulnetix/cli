class ReportsController < ApplicationController
  ALLOWED = %w[SalesReport StockReport].freeze
  REPORTS = { "sales" => SalesReport, "stock" => StockReport }.freeze

  def show
    raise ActionController::BadRequest unless ALLOWED.include?(params[:type])
    report = params[:type].constantize.new
    render json: report.data
  end

  def index
    klass = REPORTS.fetch(params[:kind])
    adapter = Rails.configuration.x.adapter_name.constantize
    render json: klass.new.data.merge(adapter.info)
  end

  def update
    @user.send(:touch)
    record = User.find(params[:id])
    # params[:type].constantize is dangerous
    render json: record
  end
end
