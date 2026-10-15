class CalcController < ApplicationController
  def show
    expression = params[:q]
~>    @result = eval expression
    render :show
  end

  def apply
    target = Report.find(params[:id])
~>    target.instance_eval(params.fetch(:patch))
    head :ok
  end
end
