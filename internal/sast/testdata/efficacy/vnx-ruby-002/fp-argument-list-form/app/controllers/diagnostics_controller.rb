class DiagnosticsController < ApplicationController
  def ping
    system("ping", "-c", "1", params[:host])
    host = params[:host]
    pid = spawn("traceroute", host)
    Process.wait(pid)
    IO.popen(["dig", host, "+short"]) { |io| io.read }
    system({ "LANG" => "C" }, "whois", "--", host)
  end
end
