class ExportsController < ApplicationController
  def create
~>    exporter = params[:type].constantize.new(current_user)
    send_data exporter.call, filename: "export.csv"
  end
end
