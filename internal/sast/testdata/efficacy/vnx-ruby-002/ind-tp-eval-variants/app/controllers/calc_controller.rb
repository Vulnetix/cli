class CalcController < ApplicationController
  def compute
~>    result = eval(params[:expression])
    render json: { result: result }
  end

  def hook
    code = request.body.read
~>    instance_eval(code)
    head :no_content
  end

  def define
~>    Widget.class_eval("def #{params[:name]}; end")
    head :ok
  end
end
