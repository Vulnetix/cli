class DiagnosticsController < ApplicationController
  def ping
    host = params[:host].to_s.strip
    target = host.downcase
~>    @output = `ping -c 3 #{target}`
~>    @trace = %x{traceroute #{host}}
    render :ping
  end
end
