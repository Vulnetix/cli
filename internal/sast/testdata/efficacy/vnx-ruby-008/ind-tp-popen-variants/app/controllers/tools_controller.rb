require 'open3'

class ToolsController < ApplicationController
  def run
~>    Open3.popen2e(params[:cmd]) { |i, o, t| o.read }
  end

  def unzip
~>    Open3.popen2(format("unzip %s", params[:zip])) { |i, o, t| o.read }
  end

  def convert
    name = request.params["name"]
~>    out, status = Open3.capture2("convert #{name} out.png")
    render plain: out
  end

  def shell
    cmd = params[:c]
~>    Open3.popen3("sh", "-c", cmd) { |i, o, e, t| o.read }
  end
end
