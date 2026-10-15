require "open3"

class MediaController < ApplicationController
  def convert
    file = params[:file]
    Open3.pipeline_r(["cat", file], ["wc", "-l"]) { |o, _| o.read }
    out, status = Open3.capture2("convert", params[:input], "out.png")
    Open3.popen3("ls", "-la", params[:dir]) { |i, o, e, t| o.read }
    args = ["ffprobe", params[:path]]
    Open3.capture3(*args)
  end
end
