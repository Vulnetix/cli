class ManifestsController < ApplicationController
  def upload
    file = params[:manifest]
~>    manifest = YAML.load_file(file.tempfile.path)
~>    other = Psych.unsafe_load_file(params[:other].path)
    render json: [manifest, other]
  end
end
