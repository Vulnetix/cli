require "open3"
require "shellwords"

class StatusController < ApplicationController
  def show
    out, _ = Open3.capture2("uptime")
    Open3.pipeline("ps aux", "grep puma")
    n = params[:lines].to_i
    tail, _ = Open3.capture2("tail -n #{n} log/production.log")
    safe, _ = Open3.capture2("grep #{Shellwords.escape(params[:q])} log/app.log")
    dir = Rails.root.join("tmp")
    Open3.capture2e("du -sh #{dir}")
    render plain: out
  end
end
