class UploadsController < ApplicationController
  def create
    upload = params[:file]
~>    data = YAML.load_file(upload.tempfile)
~>    rows = YAML.unsafe_load_file(params[:path])
    render json: { rows: rows.size, keys: data.keys }
  end
end
