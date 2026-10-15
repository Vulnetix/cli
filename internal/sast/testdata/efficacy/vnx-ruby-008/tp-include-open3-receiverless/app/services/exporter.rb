require "open3"

class ExportsController < ApplicationController
  include Open3

  def run
    fmt = params[:format]
~>    out, _ = capture2("pandoc -t #{fmt} doc.md")
    send_data out
  end
end
