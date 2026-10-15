require "open3"

class ToolsController < ApplicationController
  def ping
    host = params[:host]
    cmd = "ping -c 1 #{host}"
~>    out, status = Open3.capture2(cmd)
~>    stdout, stderr, st = Open3.capture3("nslookup " + host)
~>    output, _ = Open3.capture2e({ "LANG" => "C" }, "dig #{host}")
    render plain: out + stdout + output
  end
end
