class MediaController < ApplicationController
  def probe
~>    out, err, status = Open3.capture3 "ffprobe -v quiet -show_format #{params[:url]}"
~>    log, _s = ::Open3.capture2e("youtube-dl " + params[:video])
    render json: { out: out, log: log }
  end
end
