class DiagnosticsController < ApplicationController
  def ping
    host = params[:host]
~>    output = `ping -c 1 #{host}`
    render plain: output
  end

  def lookup
~>    system("dig +short #{params[:domain]}")
    head :ok
  end
end
