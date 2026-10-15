class ConvertController < ApplicationController
  def create
    name = params[:file].original_filename
    dest = "out/#{name}.pdf"
~>    Open3.capture2({ "HOME" => "/tmp" }, "libreoffice --headless --convert-to pdf #{dest}")
    send_file dest
  end
end
