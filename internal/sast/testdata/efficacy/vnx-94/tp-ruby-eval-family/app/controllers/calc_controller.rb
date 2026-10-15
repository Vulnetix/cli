class CalcController < ApplicationController
  def show
~>    render plain: eval(params[:expr]).to_s
  end

  def apply
    code = params.fetch(:code)
~>    instance_eval(code)
~>    Widget.class_eval(request.body.read)
  end

  def legacy
    snippet = "@value = #{params[:value]}"
~>    eval snippet
  end
end
