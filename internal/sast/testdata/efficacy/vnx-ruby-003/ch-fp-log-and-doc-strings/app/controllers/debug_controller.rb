class DebugController < ApplicationController
  # Never call Marshal.load(params[:blob]) here; it is remote code execution.
  def show
    logger.warn("refusing Marshal.load(#{params[:blob].inspect})")
    render plain: "JSON.load(request.body) is disabled"
  end
end
