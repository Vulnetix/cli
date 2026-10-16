class SafeController < ApplicationController
  def create
    a = YAML.safe_load(request.body.read)
    b = YAML.load(params[:more], permitted_classes: [Symbol])
    c = Psych.safe_load(params[:doc], permitted_classes: [Date])
    d = YAML.safe_load_file(params[:path])
    render json: [a, b, c, d]
  end
end
