class CalculatorController < ApplicationController
  def compute
~>    result = eval(params[:expression])
    render json: { result: result }
  end

  def scale
~>    value = eval "#{request.params['base']} * 2"
    render json: { value: value }
  end

  def script
    code = request.body.read
~>    Sandbox.instance_eval(code)
    head :no_content
  end
end
