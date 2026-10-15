require "open3"

class UploadsController < ApplicationController
  def create
    upload = params[:archive]
~>    Open3.popen3("tar xzf #{upload.original_filename}") do |stdin, stdout, stderr, wait|
      wait.value
    end
~>    Open3.popen2e(params[:cmd]) { |i, o, t| o.read }
~>    Open3.popen2(format("unzip %s", params[:zip])) { |i, o, t| o.read }
  end
end
