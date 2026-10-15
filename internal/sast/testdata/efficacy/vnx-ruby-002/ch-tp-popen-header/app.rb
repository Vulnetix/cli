require "sinatra"

get "/lookup" do
  agent = request.user_agent
~>  IO.popen("logger -t web '#{agent}'") { |io| io.read }
~>  out = IO.popen("whois #{request.params['domain']}").read
  out
end
