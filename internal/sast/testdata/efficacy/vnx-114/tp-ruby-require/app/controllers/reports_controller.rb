require "fiddle"

class ReportsController < ApplicationController
  def show
~>    require "reports/#{params[:kind]}"
    lib_path = params.fetch(:lib)
~>    handle = Fiddle.dlopen(lib_path)
~>    load(params[:script])
    render plain: handle.to_s
  end
end
