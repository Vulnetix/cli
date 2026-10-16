class ProbesController < ApplicationController
  def show
    probe_name = params[:probe]
    logger.info("running probe")
~>    result = Probe.new.send(probe_name)
    render json: { result: result }
  end
end
