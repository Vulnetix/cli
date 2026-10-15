require "sinatra"

before do
~>  @client_ip = request.env["HTTP_X_FORWARDED_FOR"] || request.ip
  halt 403 unless ALLOWED_IPS.include?(@client_ip)
end
