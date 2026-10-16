require "fiddle"

class ScriptsController < ApplicationController
  def run
~>    load Rails.root.join("scripts", "#{params[:script]}.rb").to_s
    head :ok
  end

  def native
    lib_name = params[:lib]
~>    handle = Fiddle.dlopen("/opt/native/#{lib_name}")
    render plain: handle.to_s
  end

  def report
~>    require_relative "../../reports/#{params[:kind]}_report"
    head :ok
  end
end
