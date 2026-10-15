class SafeController < ApplicationController
  def show
    config.instance_eval do
      self.timeout = 5
    end
    Widget.class_eval { attr_accessor :name }
    total = eval("1 + 1")
    # eval(params[:expr])
    n = Integer(params[:n])
    render plain: (total + n).to_s
  end
end
