class ExportsController < ApplicationController
  FORMATS = { "csv" => :to_csv, "json" => :to_json }.freeze

  def show
    method = FORMATS.fetch(params[:format], :to_json)
    render plain: @report.public_send(method)
    # never do @report.send(params[:format]) here
    note = "calls send(params[:x]) are dangerous"
  end
end
