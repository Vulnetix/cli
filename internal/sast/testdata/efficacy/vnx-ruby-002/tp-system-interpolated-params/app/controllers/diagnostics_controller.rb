class DiagnosticsController < ApplicationController
  def ping
~>    system("ping -c 1 #{params[:host]}")
    head :ok
  end

  def trace
~>    ok = system "traceroute " + params[:host]
    render plain: ok.to_s
  end

  def dig
~>    Kernel.system(
      "dig #{params[:name]} +short"
    )
  end
end
