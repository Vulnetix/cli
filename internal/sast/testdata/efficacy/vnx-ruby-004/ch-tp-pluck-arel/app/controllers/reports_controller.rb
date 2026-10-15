class ReportsController < ApplicationController
  def columns
    column = params[:column]
~>    values = Sale.pluck(Arel.sql(column))
~>    totals = Sale.group(Arel.sql(params[:by])).sum(:amount)
    render json: { values: values, totals: totals }
  end
end
