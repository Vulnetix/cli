class DocsController < ApplicationController
  # Do not call Open3.capture2("ls #{params[:dir]}") with request data.
  def show
    @example = 'Open3.pipeline("cat #{params[:file]}")'
    @q = params[:q]
    render :show
  end
end
