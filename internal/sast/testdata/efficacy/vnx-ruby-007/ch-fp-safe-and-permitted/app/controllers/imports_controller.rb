class ImportsController < ApplicationController
  def create
    data = YAML.safe_load(params[:data], permitted_classes: [Date, Symbol])
    more = Psych.safe_load(request.body.read)
    restricted = YAML.load(params[:extra], permitted_classes: [Date])
    rocket = YAML.load(params[:legacy], :permitted_classes => [Time])
    render json: [data, more, restricted, rocket]
  end
end
