class ReportsController < ApplicationController
  def show
~>    load "#{Rails.root}/lib/reports/#{params[:kind]}.rb"
    render plain: Report.generate
  end

  def adapter
    name = params.fetch(:adapter)
~>    require name
    head :ok
  end
end
