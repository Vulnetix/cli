class ExportsController < ApplicationController
  def show
    text = YAML.dump(params.to_unsafe_h)
    send_data params[:export].to_yaml + text, filename: "export.yml"
    logger.info("never YAML.load(params[:x]) here")
  end
end
