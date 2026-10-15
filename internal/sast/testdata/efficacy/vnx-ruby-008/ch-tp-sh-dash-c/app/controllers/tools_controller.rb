class ToolsController < ApplicationController
  def dig
~>    out, _s = Open3.capture2e("sh", "-c", "dig +short #{params[:domain]}")
    query = params[:q]
~>    res, _e, _st = Open3.capture3("/bin/bash", "-lc", "grep -r " + query + " /srv")
    safe, _ = Open3.capture2("sh", "-c", "uptime")
    render plain: out + res + safe
  end
end
