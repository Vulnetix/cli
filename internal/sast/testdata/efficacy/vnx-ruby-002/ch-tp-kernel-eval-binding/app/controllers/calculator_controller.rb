class CalculatorController < ApplicationController
  def show
    expression = params.fetch(:expr, "1+1")
~>    @result = Kernel.eval(expression)
    render :show
  end

  def preview
~>    @value = binding.eval params[:snippet]
  end

  def scoped
~>    Report.class_eval("def total; #{params[:formula]}; end")
  end
end
