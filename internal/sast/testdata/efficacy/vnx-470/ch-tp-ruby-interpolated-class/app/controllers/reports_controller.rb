class ReportsController < ApplicationController
  def show
~>    report = "#{params[:kind].camelize}Report".constantize.new(current_user)
    render json: report.to_h
  end
end
